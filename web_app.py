import os
import re
import secrets
import hashlib
import asyncio
import functools
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import jwt
from jwt.exceptions import InvalidTokenError
from database import db
from disney_search import disney_searcher
import logging
import httpx
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, SUPER_ADMIN_IDS, is_super_admin, BOT_TOKEN, MAX_BODY_BYTES, PRODUCTION
from rate_limiter import rate_limiter, get_client_ip
from permissions import can_use_email
from enums import SearchSource
from admin_notifications import notify_search_activity, notify_search_error

logger = logging.getLogger(__name__)

# Configuración de FastAPI
app = FastAPI(title="Disney Search Pro", description="Sistema de búsqueda de códigos Disney")

class RequestSizeLimitMiddleware:
    """Middleware ASGI para prevenir DoS limitando estrictamente el tamaño del Request Body"""
    def __init__(self, app, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        total_size = 0
        
        async def receive_wrapper():
            nonlocal total_size
            message = await receive()
            if "body" in message:
                total_size += len(message.get("body", b""))
                if total_size > self.max_body_size:
                    raise RuntimeError("Payload Too Large")
            return message

        try:
            await self.app(scope, receive_wrapper, send)
        except RuntimeError as exc:
            if str(exc) == "Payload Too Large":
                logger.warning(f"🚨 Rate limit SEARCH: Payload rechazado por exceder {self.max_body_size} bytes")
                await send({
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [(b"content-type", b"application/json")],
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"success": false, "error": "Payload Too Large: El tamano de la peticion excede el limite permitido de seguridad."}',
                })
            else:
                raise

app.add_middleware(RequestSizeLimitMiddleware, max_body_size=MAX_BODY_BYTES)

# ✅ SECURITY: Restrictive CORS Configuration
# Load allowed origins from environment variable
ALLOWED_ORIGINS_STR = os.getenv("ALLOWED_ORIGINS", "")
if ALLOWED_ORIGINS_STR == "*":
    # Only allow wildcard in development mode
    if os.getenv("PRODUCTION", "true").lower() == "true":
        raise ValueError("CORS wildcard (*) is not allowed in production. Set ALLOWED_ORIGINS in .env file")
    ALLOWED_ORIGINS = ["*"]
    logger.warning("⚠️ CORS: Wildcard origin enabled (DEVELOPMENT MODE ONLY)")
else:
    ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",") if origin.strip()]
    if not ALLOWED_ORIGINS:
        # Default to localhost for development
        ALLOWED_ORIGINS = ["http://localhost:8000", "http://127.0.0.1:8000"]
        logger.warning(f"⚠️ CORS: Using default localhost origins. Set ALLOWED_ORIGINS in production")
    logger.info(f"✅ CORS: Allowed origins configured: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # ✅ SECURE: Restricted origins from environment
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # ✅ SECURE: Only necessary methods
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],  # ✅ SECURE: Specific headers only
)

# Archivos estáticos y templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# ✅ AUDIT: Security Headers Middleware (Helmet-style)
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Añade headers de seguridad a todas las respuestas (OWASP best practices)"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class AuthManager:
    @staticmethod
    def create_access_token(user_id: int):
        """Crea token de acceso JWT"""
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode = {
            "sub": str(user_id),
            "exp": expire,
            "iat": datetime.utcnow()
        }
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    @staticmethod
    def verify_token(token: str):
        """Verifica y decodifica token JWT"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = int(payload.get("sub"))
            return user_id
        except InvalidTokenError:
            return None
    
    @staticmethod
    def create_csrf_token():
        """Crea token CSRF"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def verify_csrf_token(session_token: str, csrf_token: str):
        """Verifica token CSRF"""
        try:
            session_data = db.execute_query(
                "SELECT csrf_token FROM web_sessions WHERE session_token = %s AND is_active = TRUE",
                (session_token,)
            )
            return session_data and session_data[0]['csrf_token'] == csrf_token
        except Exception as e:
            logger.error(f"Error verificando CSRF token: {e}")
            return False

async def get_current_user(request: Request):
    """Obtiene el usuario actual de la sesión con verificaciones mejoradas"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return None

    try:
        session_data = db.execute_query("""
            SELECT s.user_id, s.expires_at, s.csrf_token,
                   u.username, u.first_name, u.is_admin, u.free_access, 
                   u.is_blocked, u.blocked_reason, u.blocked_at
            FROM web_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s AND s.is_active = TRUE
        """, (session_token,))
        
        if not session_data:
            return None
        
        session = session_data[0]
        
        # Verificar si está bloqueado y cerrar sesión automáticamente
        if session['is_blocked']:
            logger.warning(f"Usuario bloqueado detectado en sesión activa: {session['user_id']}")
            
            # Invalidar la sesión automáticamente
            try:
                db.execute_query(
                    "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                    (session_token,)
                )
                logger.info(f"🔒 Sesión invalidada automáticamente para usuario bloqueado: {session['user_id']}")
            except Exception as e:
                logger.error(f"Error invalidando sesión de usuario bloqueado: {e}")
            
            return None
        
        # Verificar expiración
        if datetime.now() > session['expires_at']:
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            return None
        
        return {
            'id': session['user_id'],
            'telegramId': session['user_id'],
            'username': session['username'],
            'firstName': session['first_name'],
            'isAdmin': session['is_admin'],
            'isSuperAdmin': is_super_admin(session['user_id']),
            'free_access': session['free_access'],
            'is_blocked': session['is_blocked'],
            'csrf_token': session['csrf_token']
        }
        
    except Exception as e:
        logger.error(f"Error obteniendo usuario actual: {e}")
        return None

async def require_auth(request: Request):
    """Requiere autenticación con verificación de estado mejorada"""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="No autenticado")
    
    if user.get('is_blocked'):
        raise HTTPException(status_code=403, detail="Usuario bloqueado")
    
    return user


# ✅ AUDIT: Endpoint de healthcheck para monitoreo
@app.get("/health")
async def health_check():
    """Endpoint de salud para monitoreo y load balancers"""
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.0.0"
    }

    # Verificar conexión a DB
    try:
        db.execute_query("SELECT 1")
        health["database"] = "connected"
    except Exception:
        health["database"] = "disconnected"
        health["status"] = "degraded"

    status_code = 200 if health["status"] == "healthy" else 503
    return JSONResponse(content=health, status_code=status_code)

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard principal con restricciones para admins"""
    user = await get_current_user(request)
    
    if not user:
        return RedirectResponse(url="/login", status_code=302)
    
    if user.get('is_blocked'):
        return RedirectResponse(url="/login", status_code=302)
    
    try:
        # Obtener estadísticas
        total_searches = db.execute_query(
            "SELECT COUNT(*) as count FROM disney_searches WHERE user_id = %s",
            (user['id'],)
        )
        
        search_count = total_searches[0]['count'] if total_searches else 0
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "user": user,
            "search_count": search_count
        })
        
    except Exception as e:
        logger.error(f"Error cargando dashboard: {e}")
        return RedirectResponse(url="/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Página de login con redirección inteligente"""
    user = await get_current_user(request)
    if user and not user.get('is_blocked'):
        return RedirectResponse(url="/", status_code=302)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/api/login")
async def login_api(request: Request):
    """🔒 API de login con rate limiting y validación mejorada"""
    try:
        data = await request.json()
        telegram_id_str = data.get('telegramId', '').strip()

        # Obtener IP del cliente
        client_ip = get_client_ip(request)

        if not telegram_id_str:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "ID de Telegram requerido"}
            )

        try:
            user_id = int(telegram_id_str)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "ID de Telegram inválido"}
            )

        # ✅ RATE LIMITING: Verificar límite de intentos de login
        can_attempt, error_message = rate_limiter.check_login_rate_limit(user_id, client_ip)
        if not can_attempt:
            logger.warning(f"🚨 Rate limit LOGIN: Usuario {user_id} bloqueado desde IP {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": error_message}
            )
        
        # Verificar si el usuario existe y está activo
        user_data = db.execute_query("""
            SELECT id, username, first_name, is_admin, free_access, expires_at, is_active, is_blocked, blocked_reason
            FROM users WHERE id = %s
        """, (user_id,))

        # ✅ PROTECCIÓN CONTRA ENUMERACIÓN: Mensaje genérico para todos los casos de error
        generic_error = "Credenciales inválidas o acceso no autorizado"

        if not user_data:
            # ✅ Registrar intento fallido (usuario no existe)
            rate_limiter.record_login_attempt(user_id, client_ip, False)
            logger.warning(f"🚫 Intento de login con ID inexistente: {user_id} desde IP {client_ip}")
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": generic_error}
            )

        user = user_data[0]

        if user['is_blocked']:
            # ✅ Registrar intento fallido (usuario bloqueado)
            rate_limiter.record_login_attempt(user_id, client_ip, False)
            reason = user['blocked_reason'] or "Usuario bloqueado"
            logger.warning(f"🚫 Intento de login de usuario bloqueado: {user_id} - Razón: {reason}")
            return JSONResponse(
                status_code=403,
                content={"success": False, "error": f"Cuenta bloqueada: {reason}"}
            )

        if not user['is_active']:
            # ✅ Registrar intento fallido (usuario inactivo)
            rate_limiter.record_login_attempt(user_id, client_ip, False)
            logger.warning(f"🚫 Intento de login de usuario inactivo: {user_id}")
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": generic_error}
            )

        if user['expires_at'] and datetime.now() > user['expires_at']:
            # ✅ Registrar intento fallido (acceso expirado)
            rate_limiter.record_login_attempt(user_id, client_ip, False)
            logger.warning(f"🚫 Intento de login con acceso expirado: {user_id}")
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Acceso expirado"}
            )
        
        # --- NUEVO FLUJO OTP ---
        # 1. Generar OTP
        otp_code = f"{secrets.randbelow(1000000):06d}"
        # ✅ SECURITY: Never log OTP codes
        logger.info(f"🔐 OTP generado para usuario {user_id}")

        # 2. Guardar OTP en BD
        if db.save_otp(user_id, otp_code):
            logger.info(f"✅ OTP guardado exitosamente en BD para usuario {user_id}")
            # 3. Enviar OTP por Telegram
            try:
                msg_text = f"🔐 *Disney Search Pro*\n\nTu código de verificación es: `{otp_code}`\n\nVálido por 5 minutos."
                async with httpx.AsyncClient() as client:
                    await client.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                        json={
                            "chat_id": user_id,
                            "text": msg_text,
                            "parse_mode": "Markdown"
                        },
                        timeout=5.0
                    )
                logger.info(f"✉️ OTP enviado a Telegram para usuario {user_id}")

                # ✅ Registrar intento de login exitoso (OTP enviado)
                rate_limiter.record_login_attempt(user_id, client_ip, True)

                return JSONResponse(content={
                    "success": True,
                    "step": "otp_verification",
                    "userId": user_id,
                    "message": "Código enviado a Telegram"
                })
            except Exception as e:
                logger.error(f"Error enviando OTP a Telegram: {e}")
                # ✅ Registrar fallo en envío de OTP
                rate_limiter.record_login_attempt(user_id, client_ip, False)
                return JSONResponse(
                    status_code=500,
                    content={"success": False, "error": "Error enviando código a Telegram"}
                )
        else:
            # ✅ Registrar fallo en generación de OTP
            rate_limiter.record_login_attempt(user_id, client_ip, False)
            return JSONResponse(
                status_code=500,
                content={"success": False, "error": "Error generando código de seguridad"}
            )
        
    except Exception as e:
        logger.error(f"Error en login: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Error interno del servidor"}
        )

@app.post("/api/verify-otp")
async def verify_otp_api(request: Request):
    """🔒 CRÍTICO: Verifica OTP con rate limiting contra fuerza bruta"""
    try:
        data = await request.json()
        user_id = data.get('userId')
        otp_code = data.get('otp')

        # Obtener IP del cliente
        client_ip = get_client_ip(request)

        # ✅ SECURITY: Never log OTP codes
        logger.info(f"🔍 Solicitud de verificación OTP - UserID: {user_id} desde IP: {client_ip}")

        if not user_id or not otp_code:
            return JSONResponse(status_code=400, content={"success": False, "error": "Datos incompletos"})

        try:
            user_id = int(str(user_id).strip())
        except:
             return JSONResponse(status_code=400, content={"success": False, "error": "ID inválido"})

        # ✅ RATE LIMITING CRÍTICO: Verificar límite de intentos OTP (PREVIENE FUERZA BRUTA)
        can_attempt, error_message = rate_limiter.check_otp_rate_limit(user_id, client_ip)
        if not can_attempt:
            logger.warning(f"🚨 Rate limit OTP: Usuario {user_id} bloqueado desde IP {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"success": False, "error": error_message}
            )

        # Verificar OTP
        logger.info(f"🔐 Intentando verificar OTP para usuario {user_id}")
        if not db.verify_otp(user_id, otp_code):
            # ✅ Registrar intento OTP fallido
            rate_limiter.record_otp_attempt(user_id, client_ip, False)
            logger.warning(f"❌ OTP inválido para usuario {user_id} desde IP {client_ip}")
            return JSONResponse(
                status_code=400,
                content={"success": False, "error": "Código inválido o expirado"}
            )

        # ✅ OTP CORRECTO: Registrar intento exitoso
        rate_limiter.record_otp_attempt(user_id, client_ip, True)

        # DEBUG: Verificar emails asignados inmediatamente después del login exitoso
        logger.info(f"🔍 DEBUG - Verificando emails asignados después del login exitoso para usuario {user_id}")
        db.get_user_emails_debug(user_id)

        # Obtener datos de usuario para respuesta
        user_data = db.execute_query("SELECT id, username, first_name FROM users WHERE id = %s", (user_id,))
        if not user_data:
             return JSONResponse(status_code=400, content={"success": False, "error": "Usuario no encontrado"})
        user = user_data[0]

        # Crear sesión (Lógica movida desde login anterior)
        session_token = secrets.token_urlsafe(32)
        csrf_token = AuthManager.create_csrf_token()
        expires_at = datetime.now() + timedelta(hours=24)
        
        # Invalidar sesiones anteriores
        db.execute_query("""
            UPDATE web_sessions 
            SET is_active = FALSE 
            WHERE user_id = %s AND is_active = TRUE
        """, (user_id,))
        
        # Crear nueva sesión
        db.execute_query("""
            INSERT INTO web_sessions (user_id, session_token, csrf_token, expires_at)
            VALUES (%s, %s, %s, %s)
        """, (user_id, session_token, csrf_token, expires_at))
        
        # Crear respuesta con cookie
        response = JSONResponse(content={
            "success": True,
            "user": {
                "id": user['id'],
                "telegramId": user['id'],
                "username": user['username'],
                "firstName": user['first_name']
            }
        })
        
        # ✅ SECURITY: Secure session cookie configuration
        is_production = os.getenv("PRODUCTION", "true").lower() == "true"
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=86400,  # 24 hours
            httponly=True,  # ✅ Prevents JavaScript access
            secure=is_production,  # ✅ HTTPS only in production
            samesite="strict",  # ✅ CHANGED: strict prevents CSRF attacks
            domain=None,  # ✅ Current domain only
            path="/"
        )
        
        logger.info(f"✅ Login completado (OTP verificado) para usuario {user_id}")
        return response

    except Exception as e:
        logger.error(f"Error en verificación OTP: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Error interno del servidor"}
        )

@app.get("/api/csrf-token")
async def get_csrf_token(request: Request):
    """Obtiene token CSRF con manejo mejorado"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        # ✅ AUDIT: Generar token temporal para formulario de login (pre-autenticación)
        csrf_token = AuthManager.create_csrf_token()
        return JSONResponse(content={"csrfToken": csrf_token})
    
    try:
        session_data = db.execute_query(
            "SELECT csrf_token FROM web_sessions WHERE session_token = %s AND is_active = TRUE",
            (session_token,)
        )
        
        if session_data:
            return JSONResponse(content={"csrfToken": session_data[0]['csrf_token']})
        else:
            csrf_token = AuthManager.create_csrf_token()
            return JSONResponse(content={"csrfToken": csrf_token})
            
    except Exception as e:
        logger.error(f"Error obteniendo CSRF token: {e}")
        csrf_token = AuthManager.create_csrf_token()
        return JSONResponse(content={"csrfToken": csrf_token})

@app.get("/api/auth/check")
async def check_auth(user = Depends(require_auth)):
    """Verifica autenticación"""
    return JSONResponse(content={
        "success": True,
        "user": user
    })

@app.get("/api/user/status")
async def check_user_status(request: Request):
    """Verifica específicamente el estado del usuario (bloqueado, activo, etc.)"""
    session_token = request.cookies.get("session_token")
    
    if not session_token:
        return JSONResponse(
            status_code=401,
            content={"success": False, "error": "No hay sesión activa"}
        )
    
    try:
        session_data = db.execute_query("""
            SELECT s.user_id, s.expires_at, u.is_blocked, u.blocked_reason, u.blocked_at
            FROM web_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = %s AND s.is_active = TRUE
        """, (session_token,))
        
        if not session_data:
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Sesión inválida"}
            )
        
        session = session_data[0]
        
        # Si está bloqueado, invalidar la sesión y devolver información del bloqueo
        if session['is_blocked']:
            # Invalidar la sesión automáticamente
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            
            return JSONResponse(content={
                "success": False,
                "blocked": True,
                "blocked_reason": session['blocked_reason'],
                "blocked_at": session['blocked_at'].isoformat() if session['blocked_at'] else None,
                "message": f"Usuario bloqueado: {session['blocked_reason'] or 'Sin razón especificada'}"
            })
        
        # Verificar expiración
        if datetime.now() > session['expires_at']:
            db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            return JSONResponse(
                status_code=401,
                content={"success": False, "error": "Sesión expirada"}
            )
        
        return JSONResponse(content={
            "success": True,
            "blocked": False,
            "active": True
        })
        
    except Exception as e:
        logger.error(f"Error verificando estado del usuario: {e}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": "Error interno del servidor"}
        )

@app.post("/api/auth/logout")
async def logout(request: Request):
    """Logout con limpieza mejorada"""
    session_token = request.cookies.get("session_token")
    
    if session_token:
        try:
            result = db.execute_query(
                "UPDATE web_sessions SET is_active = FALSE WHERE session_token = %s",
                (session_token,)
            )
            if result > 0:
                logger.info("✅ Sesión cerrada correctamente")
        except Exception as e:
            logger.error(f"Error en logout: {e}")
    
    response = JSONResponse(content={"success": True})
    response.delete_cookie(key="session_token")
    return response

@app.get("/api/user/emails")
async def get_user_emails(user = Depends(require_auth)):
    """Obtiene emails del usuario con restricciones estrictas para admins"""
    try:
        # Super admins: comportamiento original (sin emails específicos, pueden usar cualquiera)
        if user.get('isSuperAdmin', False):
            return JSONResponse(content={
                "emails": [],
                "email_count": -1,  # -1 indica acceso ilimitado
                "access_type": "super_admin",
                "message": "Acceso total a todos los emails"
            })

        # Admins normales: SOLO emails asignados específicamente
        if user.get('isAdmin', False):
            email_data = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
                (user['id'],)
            )
            email_count = len(email_data) if email_data else 0
            return JSONResponse(content={
                "emails": [],  # Oculto por seguridad
                "email_count": email_count,  # Pero enviamos el conteo
                "access_type": "admin_restricted",
                "message": f"Solo puedes usar {email_count} email{'s' if email_count != 1 else ''} asignado{'s' if email_count != 1 else ''} específicamente"
            })

        # Usuarios con acceso libre
        if user.get('free_access', False):
            return JSONResponse(content={
                "emails": [],  # Oculto
                "email_count": -1,  # -1 indica acceso ilimitado
                "access_type": "free_access",
                "message": "Acceso libre a todos los emails"
            })

        # Usuarios normales: solo emails asignados
        email_data = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
            (user['id'],)
        )
        email_count = len(email_data) if email_data else 0

        # Ocultar la lista real pero enviar el conteo
        return JSONResponse(content={
            "emails": [],  # Vacío por seguridad
            "email_count": email_count,  # Conteo para validación en frontend
            "access_type": "user_restricted",
            "message": f"Tienes acceso a {email_count} email{'s' if email_count != 1 else ''} asignado{'s' if email_count != 1 else ''} (ingrésalos manualmente)"
        })
        
    except Exception as e:
        logger.error(f"Error obteniendo emails: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Error obteniendo emails"}
        )

@app.get("/api/user/active-search")
async def get_active_search(user = Depends(require_auth)):
    """✅ NUEVO: Obtiene información de búsqueda activa del usuario"""
    try:
        active_search = db.has_active_search(user['id'])

        if active_search:
            # ✅ CORRECCIÓN: Usar datetime.utcnow() para comparar con timestamps UTC
            time_elapsed = (datetime.utcnow() - active_search['started_at']).total_seconds() / 60
            return JSONResponse(content={
                "hasActiveSearch": True,
                "email": active_search['email'],
                "startedAt": active_search['started_at'].isoformat(),
                "timeElapsedMinutes": int(time_elapsed),
                "status": active_search['status']
            })
        else:
            return JSONResponse(content={
                "hasActiveSearch": False
            })

    except Exception as e:
        logger.error(f"Error obteniendo búsqueda activa: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Error obteniendo estado de búsqueda"}
        )

@app.post("/api/search-disney")
async def search_disney_api(
    request: Request,
    user = Depends(require_auth)
):
    """🔒 API de búsqueda multi-servicio con rate limiting y verificaciones case-insensitive"""
    try:
        data = await request.json()
        email = data.get('email', '').strip()
        csrf_token = data.get('csrfToken', '')
        service = data.get('service', 'disney').strip().lower()
        sub_option = data.get('subOption', '').strip()

        # Obtener IP del cliente
        client_ip = get_client_ip(request)

        # ✅ RATE LIMITING: Verificar límite de búsquedas
        can_search, error_message = rate_limiter.check_search_rate_limit(user['id'], client_ip)
        if not can_search:
            logger.warning(f"🚨 Rate limit SEARCH: Usuario {user['id']} bloqueado desde IP {client_ip}")
            return JSONResponse(
                status_code=429,
                content={"error": error_message}
            )

        # Verificar CSRF
        session_token = request.cookies.get("session_token")
        if not AuthManager.verify_csrf_token(session_token, csrf_token):
            return JSONResponse(
                status_code=403,
                content={"error": "Token CSRF inválido"}
            )
        
        # Validar email
        if not email or '@' not in email:
            return JSONResponse(
                status_code=400,
                content={"error": "Email inválido"}
            )
        
        # Validación adicional de formato de email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return JSONResponse(
                status_code=400,
                content={"error": "Formato de email inválido"}
            )
        
        # ✅ Validar servicio permitido
        from config import SERVICE_CONFIG
        valid_services = ['disney'] + list(SERVICE_CONFIG.keys())
        if service not in valid_services:
            return JSONResponse(
                status_code=400,
                content={"error": "Servicio no válido"}
            )

        # ✅ AUDIT: Usar módulo unificado de permisos (DRY)
        if not can_use_email(
            user_id=user['id'],
            email=email,
            is_admin=user.get('isAdmin', False),
            is_super=user.get('isSuperAdmin', False),
            free_access=user.get('free_access', False)
        ):
            # Mensaje diferenciado según el tipo de usuario
            if user.get('isSuperAdmin', False):
                error_msg = "Error inesperado de permisos para super administrador"
            elif user.get('isAdmin', False):
                error_msg = "Como administrador, solo puedes usar emails específicamente asignados a tu cuenta"
            elif user.get('free_access', False):
                error_msg = "Error inesperado de permisos para usuario con acceso libre"
            else:
                error_msg = "Solo puedes usar emails asignados a tu cuenta"
            
            logger.warning(f"🚫 Permiso denegado para {user['id']} usando email: {email}")
            
            return JSONResponse(
                status_code=403,
                content={"error": f"❌ Sin permisos: {error_msg}"}
            )
        
        # Log específico para admins
        if user.get('isAdmin', False) and not user.get('isSuperAdmin', False):
            logger.info(f"🛡️ Admin {user['id']} usando email asignado: {email} (verificación case-insensitive)")
        
        # ✅ FIX #5: El check de bloqueo ya fue realizado por require_auth (Depends).
        # get_current_user() lee is_blocked desde la sesión activa y require_auth
        # lanza HTTP 403 si el usuario está bloqueado — sin query extra aquí.
        
        # ═══════════════════════════════════════════════════════════════
        # Realizar búsqueda según el servicio seleccionado
        # ✅ AUDIT: Envuelto en run_in_executor para no bloquear el event loop
        # ═══════════════════════════════════════════════════════════════
        loop = asyncio.get_event_loop()

        if service == 'disney':
            # Disney: Búsqueda con verificación de 6 minutos y detección de cambio de email
            logger.info(f"🔍 Búsqueda Disney para {email} (usuario: {user['id']}, tipo: {'super_admin' if user.get('isSuperAdmin') else 'admin' if user.get('isAdmin') else 'user'})")
            result = await loop.run_in_executor(
                None,
                functools.partial(
                    disney_searcher.search_disney_codes,
                    email, user['id'], source=SearchSource.WEB
                )
            )
        else:
            # Otros servicios: Sin verificación de 6 minutos ni detección de cambio de email
            if not sub_option:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Debes seleccionar una opción de búsqueda"}
                )
            logger.info(f"🔍 Búsqueda {service}/{sub_option} para {email} (usuario: {user['id']})")
            result = await loop.run_in_executor(
                None,
                functools.partial(
                    disney_searcher.search_service_codes,
                    email, user['id'], service, sub_option, source=SearchSource.WEB
                )
            )

        if result and result.get('found'):
            logger.info(f"✅ Resultado encontrado para {email} ({service}): {result['code']}")
            # ✅ Registrar búsqueda exitosa
            rate_limiter.record_search_attempt(user['id'], client_ip, email, True)
            return JSONResponse(content={
                "found": True,
                "result": {
                    "code": result['code'],
                    "type": result['type'],
                    "email": result['email'],
                    "subject": result['subject'],
                    "date": result['date']
                }
            })
        else:
            logger.info(f"ℹ️ No se encontraron resultados de {service} para {email}")
            # ✅ Registrar búsqueda sin resultado
            rate_limiter.record_search_attempt(user['id'], client_ip, email, False)
            return JSONResponse(content={"found": False})
            
    except Exception as e:
        logger.error(f"Error en búsqueda Disney API: {e}")

        # ✅ Registrar búsqueda fallida por error (si se obtuvo el email)
        try:
            if 'email' in locals() and 'user' in locals() and 'client_ip' in locals():
                rate_limiter.record_search_attempt(user['id'], client_ip, email, False)
        except:
            pass  # No bloquear el flujo si falla el registro

        # Manejar diferentes tipos de errores
        error_message = str(e)
        if "Usuario bloqueado" in error_message:
            return JSONResponse(
                status_code=403,
                content={"error": error_message}
            )
        elif "configuración IMAP" in error_message:
            return JSONResponse(
                status_code=400,
                content={"error": f"Error de configuración: {error_message}"}
            )
        else:
            return JSONResponse(
                status_code=500,
                content={"error": f"Error en búsqueda: {error_message[:100]}"}
            )

# Middleware para logging de requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.now()
    
    # Procesar request
    response = await call_next(request)
    
    # Calcular tiempo de procesamiento
    process_time = (datetime.now() - start_time).total_seconds()
    
    # Log solo requests importantes o errores
    if response.status_code >= 400 or process_time > 2.0:
        logger.info(
            f"{request.method} {request.url.path} - "
            f"Status: {response.status_code} - "
            f"Time: {process_time:.2f}s"
        )
    
    return response

# Manejadores de errores
@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    logger.error(f"Error 500: {exc}")
    return templates.TemplateResponse("500.html", {"request": request}, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
