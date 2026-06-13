"""
🔒 RATE LIMITING MODULE - Disney Search Pro
================================================
Módulo centralizado para protección contra ataques de fuerza bruta

LÍMITES CONFIGURADOS:
- OTP: 5 intentos fallidos en 15 minutos
- Login: 5 intentos fallidos en 5 minutos
- Búsquedas: 10 búsquedas en 5 minutos

PROTECCIONES:
✅ Previene fuerza bruta de códigos OTP
✅ Previene enumeración de usuarios
✅ Previene ataques DoS mediante búsquedas masivas
✅ Tracking por IP y por usuario
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple
from psycopg2 import sql  # ✅ AUDIT: Para interpolación segura de identificadores SQL
from database import db

logger = logging.getLogger(__name__)

# ==================== CONFIGURACIÓN DE LÍMITES ====================

# Rate Limiting para OTP (CRÍTICO)
MAX_OTP_ATTEMPTS = 5           # Máximo 5 intentos fallidos
OTP_LOCKOUT_MINUTES = 15       # Bloqueo de 15 minutos

# Rate Limiting para Login
MAX_LOGIN_ATTEMPTS = 5         # Máximo 5 intentos fallidos
LOGIN_LOCKOUT_MINUTES = 5      # Bloqueo de 5 minutos

# Rate Limiting para Búsquedas
MAX_SEARCH_ATTEMPTS = 10       # Máximo 10 búsquedas
SEARCH_LOCKOUT_MINUTES = 5     # Bloqueo de 5 minutos

# ==================== RATE LIMITER CLASS ====================

class RateLimiter:
    """
    Gestor centralizado de rate limiting con tracking en base de datos
    """

    def __init__(self):
        """Inicializa el rate limiter"""
        logger.info("🔒 Rate Limiter inicializado")

    # ==================== OTP RATE LIMITING ====================

    def check_otp_rate_limit(self, user_id: int, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica si el usuario puede intentar verificar OTP

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP

        Returns:
            (permitido: bool, mensaje_error: Optional[str])
        """
        try:
            # Verificar intentos recientes
            cutoff_time = datetime.now() - timedelta(minutes=OTP_LOCKOUT_MINUTES)

            attempts = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_otp
                WHERE user_id = %s
                  AND attempt_time > %s
                  AND success = FALSE
            """, (user_id, cutoff_time))

            attempt_count = attempts[0]['count'] if attempts else 0

            if attempt_count >= MAX_OTP_ATTEMPTS:
                # Calcular tiempo restante de bloqueo
                oldest_attempt = db.execute_query("""
                    SELECT attempt_time
                    FROM rate_limit_otp
                    WHERE user_id = %s
                      AND attempt_time > %s
                      AND success = FALSE
                    ORDER BY attempt_time ASC
                    LIMIT 1
                """, (user_id, cutoff_time))

                if oldest_attempt:
                    unlock_time = oldest_attempt[0]['attempt_time'] + timedelta(minutes=OTP_LOCKOUT_MINUTES)
                    remaining = (unlock_time - datetime.now()).total_seconds() / 60

                    logger.warning(f"🚨 Rate limit OTP: Usuario {user_id} bloqueado ({attempt_count} intentos)")

                    return False, f"Demasiados intentos fallidos. Espera {int(remaining) + 1} minuto(s) antes de intentar nuevamente."

            return True, None

        except Exception as e:
            logger.error(f"❌ Error verificando rate limit OTP: {e}")
            # En caso de error, permitir para no bloquear usuarios legítimos
            return True, None

    def record_otp_attempt(self, user_id: int, ip_address: str, success: bool):
        """
        Registra un intento de verificación OTP

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP
            success: Si el intento fue exitoso
        """
        try:
            db.execute_query("""
                INSERT INTO rate_limit_otp (user_id, ip_address, success)
                VALUES (%s, %s, %s)
            """, (user_id, ip_address, success))

            if success:
                # Limpiar intentos fallidos previos después de éxito
                self._cleanup_failed_attempts('rate_limit_otp', user_id)
                logger.info(f"✅ OTP exitoso para usuario {user_id} - intentos fallidos limpiados")
            else:
                logger.warning(f"❌ Intento OTP fallido para usuario {user_id} desde IP {ip_address}")

        except Exception as e:
            logger.error(f"❌ Error registrando intento OTP: {e}")

    # ==================== LOGIN RATE LIMITING ====================

    def check_login_rate_limit(self, user_id: int, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica si el usuario puede intentar login

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP

        Returns:
            (permitido: bool, mensaje_error: Optional[str])
        """
        try:
            cutoff_time = datetime.now() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)

            # Verificar intentos por usuario
            user_attempts = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_login
                WHERE user_id = %s
                  AND attempt_time > %s
                  AND success = FALSE
            """, (user_id, cutoff_time))

            user_count = user_attempts[0]['count'] if user_attempts else 0

            # Verificar intentos por IP (protección adicional)
            ip_attempts = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_login
                WHERE ip_address = %s
                  AND attempt_time > %s
                  AND success = FALSE
            """, (ip_address, cutoff_time))

            ip_count = ip_attempts[0]['count'] if ip_attempts else 0

            if user_count >= MAX_LOGIN_ATTEMPTS:
                logger.warning(f"🚨 Rate limit Login: Usuario {user_id} bloqueado ({user_count} intentos)")
                return False, f"Demasiados intentos de login. Espera {LOGIN_LOCKOUT_MINUTES} minuto(s)."

            if ip_count >= MAX_LOGIN_ATTEMPTS * 2:  # Límite más alto para IP
                logger.warning(f"🚨 Rate limit Login: IP {ip_address} bloqueada ({ip_count} intentos)")
                return False, f"Demasiados intentos desde esta IP. Espera {LOGIN_LOCKOUT_MINUTES} minuto(s)."

            return True, None

        except Exception as e:
            logger.error(f"❌ Error verificando rate limit Login: {e}")
            return True, None

    def record_login_attempt(self, user_id: int, ip_address: str, success: bool):
        """
        Registra un intento de login

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP
            success: Si el intento fue exitoso
        """
        try:
            db.execute_query("""
                INSERT INTO rate_limit_login (user_id, ip_address, success)
                VALUES (%s, %s, %s)
            """, (user_id, ip_address, success))

            if success:
                self._cleanup_failed_attempts('rate_limit_login', user_id)
                logger.info(f"✅ Login exitoso para usuario {user_id} - intentos fallidos limpiados")
            else:
                logger.warning(f"❌ Intento login fallido para usuario {user_id} desde IP {ip_address}")

        except Exception as e:
            logger.error(f"❌ Error registrando intento login: {e}")

    # ==================== SEARCH RATE LIMITING ====================

    def check_search_rate_limit(self, user_id: int, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Verifica si el usuario puede realizar búsquedas

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP

        Returns:
            (permitido: bool, mensaje_error: Optional[str])
        """
        try:
            cutoff_time = datetime.now() - timedelta(minutes=SEARCH_LOCKOUT_MINUTES)

            attempts = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_search
                WHERE user_id = %s
                  AND attempt_time > %s
            """, (user_id, cutoff_time))

            attempt_count = attempts[0]['count'] if attempts else 0

            if attempt_count >= MAX_SEARCH_ATTEMPTS:
                logger.warning(f"🚨 Rate limit Search: Usuario {user_id} bloqueado ({attempt_count} búsquedas)")
                return False, f"Demasiadas búsquedas. Espera {SEARCH_LOCKOUT_MINUTES} minuto(s)."

            return True, None

        except Exception as e:
            logger.error(f"❌ Error verificando rate limit Search: {e}")
            return True, None

    def record_search_attempt(self, user_id: int, ip_address: str, email: str, success: bool):
        """
        Registra un intento de búsqueda

        Args:
            user_id: ID del usuario
            ip_address: Dirección IP
            email: Email buscado
            success: Si se encontró resultado
        """
        try:
            db.execute_query("""
                INSERT INTO rate_limit_search (user_id, ip_address, email, success)
                VALUES (%s, %s, %s, %s)
            """, (user_id, ip_address, email, success))

            logger.info(f"🔍 Búsqueda registrada: Usuario {user_id}, Email: {email}, Éxito: {success}")

        except Exception as e:
            logger.error(f"❌ Error registrando búsqueda: {e}")

    # ==================== UTILIDADES ====================

    # ✅ AUDIT: Whitelist de tablas válidas para prevenir SQL injection
    _VALID_TABLES = frozenset({'rate_limit_otp', 'rate_limit_login', 'rate_limit_search'})

    def _validate_table(self, table: str) -> str:
        """Valida que el nombre de tabla sea uno de los permitidos"""
        if table not in self._VALID_TABLES:
            raise ValueError(f"Tabla no permitida: {table}")
        return table

    def _cleanup_failed_attempts(self, table: str, user_id: int):
        """
        Limpia intentos fallidos después de un intento exitoso

        Args:
            table: Nombre de la tabla
            user_id: ID del usuario
        """
        try:
            safe_table = self._validate_table(table)
            # ✅ AUDIT: Interpolación segura con psycopg2.sql
            query = sql.SQL("DELETE FROM {} WHERE user_id = %s AND success = FALSE").format(
                sql.Identifier(safe_table)
            )
            db.execute_query(query, (user_id,))
        except Exception as e:
            logger.error(f"❌ Error limpiando intentos fallidos: {e}")

    def cleanup_old_records(self, days: int = 7):
        """
        Limpia registros antiguos de rate limiting

        Args:
            days: Días de antigüedad para eliminar
        """
        try:
            cutoff_time = datetime.now() - timedelta(days=days)

            tables = ['rate_limit_otp', 'rate_limit_login', 'rate_limit_search']
            total_deleted = 0

            for table in tables:
                safe_table = self._validate_table(table)
                # ✅ AUDIT: Interpolación segura con psycopg2.sql
                query = sql.SQL("DELETE FROM {} WHERE attempt_time < %s").format(
                    sql.Identifier(safe_table)
                )
                result = db.execute_query(query, (cutoff_time,))

                if result > 0:
                    total_deleted += result
                    logger.info(f"🧹 {result} registros antiguos eliminados de {table}")

            if total_deleted > 0:
                logger.info(f"✅ Limpieza completada: {total_deleted} registros eliminados en total")

        except Exception as e:
            logger.error(f"❌ Error limpiando registros antiguos: {e}")

    def get_user_attempts_summary(self, user_id: int) -> Dict:
        """
        Obtiene resumen de intentos de un usuario

        Args:
            user_id: ID del usuario

        Returns:
            Diccionario con estadísticas
        """
        try:
            summary = {
                'otp_attempts': 0,
                'login_attempts': 0,
                'search_attempts': 0,
                'is_blocked_otp': False,
                'is_blocked_login': False,
                'is_blocked_search': False
            }

            # OTP attempts
            otp_cutoff = datetime.now() - timedelta(minutes=OTP_LOCKOUT_MINUTES)
            otp_data = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_otp
                WHERE user_id = %s AND attempt_time > %s AND success = FALSE
            """, (user_id, otp_cutoff))

            summary['otp_attempts'] = otp_data[0]['count'] if otp_data else 0
            summary['is_blocked_otp'] = summary['otp_attempts'] >= MAX_OTP_ATTEMPTS

            # Login attempts
            login_cutoff = datetime.now() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
            login_data = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_login
                WHERE user_id = %s AND attempt_time > %s AND success = FALSE
            """, (user_id, login_cutoff))

            summary['login_attempts'] = login_data[0]['count'] if login_data else 0
            summary['is_blocked_login'] = summary['login_attempts'] >= MAX_LOGIN_ATTEMPTS

            # Search attempts
            search_cutoff = datetime.now() - timedelta(minutes=SEARCH_LOCKOUT_MINUTES)
            search_data = db.execute_query("""
                SELECT COUNT(*) as count
                FROM rate_limit_search
                WHERE user_id = %s AND attempt_time > %s
            """, (user_id, search_cutoff))

            summary['search_attempts'] = search_data[0]['count'] if search_data else 0
            summary['is_blocked_search'] = summary['search_attempts'] >= MAX_SEARCH_ATTEMPTS

            return summary

        except Exception as e:
            logger.error(f"❌ Error obteniendo resumen de intentos: {e}")
            return {}

    def reset_user_limits(self, user_id: int):
        """
        Resetea todos los límites de un usuario (uso administrativo)

        Args:
            user_id: ID del usuario
        """
        try:
            tables = ['rate_limit_otp', 'rate_limit_login', 'rate_limit_search']

            for table in tables:
                safe_table = self._validate_table(table)
                # ✅ AUDIT: Interpolación segura con psycopg2.sql
                query = sql.SQL("DELETE FROM {} WHERE user_id = %s").format(
                    sql.Identifier(safe_table)
                )
                db.execute_query(query, (user_id,))

            logger.info(f"🔓 Límites reseteados para usuario {user_id}")

        except Exception as e:
            logger.error(f"❌ Error reseteando límites: {e}")

# ==================== INSTANCIA GLOBAL ====================

rate_limiter = RateLimiter()

# ==================== FUNCIONES DE UTILIDAD ====================

def get_client_ip(request) -> str:
    """
    Obtiene la IP real del cliente considerando proxies

    Args:
        request: Objeto Request de FastAPI

    Returns:
        IP del cliente
    """
    # Intentar obtener IP real desde headers de proxy
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fallback a IP directa
    return request.client.host if request.client else "unknown"
