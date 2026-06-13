import imaplib
import email
import re
import logging
import asyncio
import threading  # Needed for notify_admins_email_change + async fallback
import time
from datetime import datetime, timedelta, timezone
from email.header import decode_header
from config import DISNEY_PATTERNS, DISNEY_FROM_ADDRESSES, SUPER_ADMIN_IDS, VERIFICATION_DELAY_SECONDS, SERVICE_CONFIG
from database import db
from enums import SearchSource, SearchStatus
from admin_notifications import notify_search_activity, notify_search_error

logger = logging.getLogger(__name__)

class DisneySearcher:
    def __init__(self):
        self.connections = {}
        self._verification_tasks = {}  # ✅ AUDIT: asyncio tasks en vez de threads
        
        # Patrones para detectar cambios de email
        self.email_change_patterns = [
            r'Se cambi(?:=C3=B3|ó) el correo electr(?:=C3=B3|ó)nico(?:=)?',
            r'Correo electr(?:=C3=B3|ó)nico de MyDisney actua(?:=)?',
            r';">[\s]*MyDisney unique email address updated[\s]*</td>'
        ]
    
    def get_imap_config(self, email_addr):
        """Obtiene configuración IMAP para un dominio (password descifrada en memoria).

        ✅ FIX #3: Delega a db.get_imap_config_secure() para garantizar que
        la password nunca se devuelve en texto plano desde la BD.
        Las filas legacy sin cifrar se migran automáticamente on-read.
        """
        try:
            if '@' not in email_addr:
                raise ValueError("Email inválido")

            # Normalizar email extrayendo y limpiando el dominio
            domain = email_addr.split('@')[1].strip().lower()

            # ✅ INTENTO 1: Buscar configuración específica del dominio
            config = db.get_imap_config_secure(domain)

            # ✅ INTENTO 2: Fallback a gmail.com si no existe el dominio específico
            if not config:
                if domain != "gmail.com":
                    logger.info(f"Dominio {domain} no configurado. Utilizando fallback a gmail.com")
                
                config = db.get_imap_config_secure("gmail.com")
                
                if not config:
                    raise ValueError(
                        f"No hay configuración IMAP activa para el dominio '{domain}'. "
                        "Tampoco existe la configuración de fallback por defecto para 'gmail.com'. "
                        "Por favor contacta al administrador."
                    )
            else:
                if domain != "gmail.com":
                    logger.info(f"Utilizando configuración IMAP específica encontrada para el dominio: {domain}")

            # Extraer y limpiar el servidor para evitar errores de DNS (Name Resolution)
            # causados por espacios invisibles o retornos de carro
            server = config['server'].strip()

            # Devolver solo los campos necesarios (sin exponer 'domain' extra)
            return {
                'email': config['email'],
                'password': config['password'],   # en claro solo en memoria
                'server': server,
                'port': config['port']
            }
        except Exception as e:
            logger.error(f"Error obteniendo configuración IMAP para dominio de {email_addr}: {e}")
            raise

    
    def connect_imap(self, config):
        """Conecta a servidor IMAP con reintentos"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                conn = imaplib.IMAP4_SSL(config['server'], config['port'])
                conn.login(config['email'], config['password'])
                conn.select('INBOX')
                return conn
            except Exception as e:
                logger.error(f"Error conectando IMAP (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise
    
    def search_disney_codes(self, email_addr, user_id, source=SearchSource.TELEGRAM):
        """Busca códigos Disney en el email especificado

        Args:
            email_addr: Email donde buscar códigos
            user_id: ID del usuario que solicita
            source: Origen de la solicitud ('telegram' o 'web')
        """
        conn = None
        try:
            # ✅ NUEVO: Verificar si el usuario tiene skip_verification activado
            user_verification_status = db.execute_query(
                "SELECT skip_verification FROM users WHERE id = %s",
                (user_id,)
            )

            skip_verification = False
            if user_verification_status and user_verification_status[0].get('skip_verification', False):
                skip_verification = True
                logger.info(f"🔓 Usuario {user_id} tiene skip_verification activado - saltando verificación de 6 minutos")

            # ✅ VERIFICACIÓN MULTI-PLATAFORMA: Verificar si hay búsqueda activa (sin importar la plataforma)
            # Solo si el usuario NO tiene skip_verification activado
            if not skip_verification:
                active_search = db.has_active_search(user_id)
            else:
                # Usuario excluido - limpiar cualquier búsqueda activa previa
                db.end_search_request(user_id)
                active_search = None

            if active_search:
                # ✅ CORRECCIÓN DEFINITIVA: Usar datetime.now(timezone.utc) para comparar con timestamps UTC
                # Esto asegura comparación correcta con TIMESTAMPTZ de PostgreSQL
                current_time = datetime.now(timezone.utc)
                started_at = active_search['started_at']

                # Asegurar que started_at sea timezone-aware
                if started_at.tzinfo is None:
                    started_at = started_at.replace(tzinfo=timezone.utc)

                time_elapsed = (current_time - started_at).total_seconds() / 60

                # Log detallado para debugging de timestamps
                logger.info(f"⏰ Verificación de tiempo - Usuario {user_id}: current={current_time.isoformat()}, started={started_at.isoformat()}, elapsed={time_elapsed:.2f} min")

                # ✅ SEGURIDAD: Ya no debería haber tiempos negativos con TIMESTAMPTZ
                # Pero mantenemos validación por si acaso
                if time_elapsed < 0:
                    # Si hay tiempo negativo, es un error grave - reportar y tratar como búsqueda reciente
                    logger.error(f"🚨 Timestamp con diferencia negativa ({time_elapsed:.1f} min) - ERROR DE SISTEMA")
                    time_elapsed = 0  # Tratar como búsqueda recién iniciada

                # ✅ SAFETY: Si la búsqueda es muy antigua (más de 10 min), eliminarla y continuar
                if time_elapsed > 10:
                    logger.warning(f"🧹 Búsqueda obsoleta detectada para usuario {user_id} ({time_elapsed:.0f} min). Limpiando...")
                    db.end_search_request(user_id)
                    # Continuar con la nueva búsqueda (no bloquear)
                else:
                    # Búsqueda válida (entre 0 y 10 minutos)
                    time_remaining = max(1, 6 - time_elapsed)  # Mínimo 1 minuto para evitar 0

                    # Determinar de dónde viene la búsqueda activa
                    active_source = active_search['source']
                    source_text = {
                        'telegram': '🤖 Telegram Bot',
                        'web': '🌐 Página Web'
                    }

                    # Determinar desde dónde está intentando buscar ahora
                    current_source_text = source_text.get(source, source)
                    active_source_text = source_text.get(active_source, active_source)

                    if time_elapsed < 6:
                        # Dentro del período de verificación (0-6 minutos)
                        raise Exception(
                            f"⏳ BÚSQUEDA EN VERIFICACIÓN\n\n"
                            f"📧 Email: {active_search['email']}\n"
                            f"📍 Iniciada desde: {active_source_text}\n"
                            f"🔒 Tiempo de verificación: {max(0, int(time_elapsed))}/6 minutos\n"
                            f"⏰ Tiempo restante: ~{int(time_remaining)} minuto(s)\n\n"
                            f"❌ No puedes buscar desde {current_source_text} mientras tengas una verificación activa.\n"
                            f"💡 La verificación de seguridad se aplica en todas las plataformas (Bot y Web).\n"
                            f"⏳ Espera {int(time_remaining)} minuto(s) más para poder buscar nuevamente."
                        )
                    else:
                        # Entre 6 y 10 minutos (verificación completada pero no finalizada)
                        logger.warning(f"🧹 Búsqueda completada pero no finalizada para usuario {user_id}. Limpiando...")
                        db.end_search_request(user_id)
                        # Continuar con la nueva búsqueda

            # Verificar si el usuario está bloqueado
            user_status = db.execute_query(
                "SELECT is_blocked, blocked_reason FROM users WHERE id = %s",
                (user_id,)
            )

            if user_status and user_status[0]['is_blocked']:
                reason = user_status[0]['blocked_reason'] or "Usuario bloqueado"
                raise Exception(f"Usuario bloqueado: {reason}")

            # ✅ CRÍTICO: Registrar inicio de búsqueda ANTES de buscar códigos
            # Esto asegura que la búsqueda se registre incluso si encuentra código
            # PERO solo si el usuario NO tiene skip_verification activado
            if not skip_verification:
                if not db.start_search_request(user_id, email_addr, source):
                    raise Exception("No se pudo iniciar la búsqueda. Intenta de nuevo en unos momentos.")
                logger.info(f"🔍 Búsqueda registrada para usuario {user_id} - Email: {email_addr} - Source: {source}")
            else:
                logger.info(f"🔓 Búsqueda sin registro para usuario {user_id} (skip_verification activo) - Email: {email_addr} - Source: {source}")

            config = self.get_imap_config(email_addr)
            conn = self.connect_imap(config)
            
            # Buscar emails de los últimos 2 días
            date_since = (datetime.now() - timedelta(days=2)).strftime("%d-%b-%Y")
            
            # Construir criterio de búsqueda
            search_criteria = []
            for from_addr in DISNEY_FROM_ADDRESSES:
                search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')
            
            combined_criteria = f'OR {" ".join(search_criteria)}' if len(search_criteria) > 1 else search_criteria[0]
            
            # Buscar mensajes
            status, messages = conn.search(None, combined_criteria)
            
            if not messages[0]:
                logger.info(f"No se encontraron emails Disney para {email_addr}")
                return {'found': False, 'email': email_addr}
            
            # Procesar mensajes (más recientes primero)
            message_ids = messages[0].split()
            message_ids.reverse()
            
            # Probar cada patrón regex
            for msg_id in message_ids[:10]:  # Solo los 10 más recientes
                try:
                    # Obtener mensaje completo
                    status, msg_data = conn.fetch(msg_id, '(RFC822)')
                    if not msg_data or not msg_data[0] or not msg_data[0][1]:
                        continue
                        
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    # Extraer información del email
                    subject = self.decode_subject(email_message.get('Subject', ''))
                    from_addr = email_message.get('From', '')
                    date_str = email_message.get('Date', '')
                    
                    # Obtener cuerpo del mensaje
                    body = self.extract_body(email_message)
                    
                    if not body:
                        continue
                    
                    # Probar cada patrón Disney
                    for pattern_name, pattern in DISNEY_PATTERNS.items():
                        try:
                            regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                            match = regex.search(body)
                            
                            if match:
                                code = match.group(1) if match.groups() else match.group(0)
                                
                                # Limpiar código
                                code = code.strip()
                                
                                if not code:
                                    continue
                                
                                # Determinar tipo de código
                                code_type = self.determine_code_type(pattern_name, subject, from_addr)
                                
                                result = {
                                    'found': True,
                                    'code': code,
                                    'type': code_type,
                                    'email': email_addr,
                                    'subject': subject,
                                    'date': date_str,
                                    'pattern_used': pattern_name
                                }
                                
                                # Guardar búsqueda en BD
                                search_id = self.save_search_result(user_id, email_addr, code_type, code)

                                # ✅ Programar verificación de cambio de email (async)
                                if search_id:
                                    self.schedule_email_verification(search_id, user_id, email_addr, code)
                                    if not skip_verification:
                                        logger.info(f"🔒 Búsqueda activa mantenida para {email_addr} durante verificación (6 min)")

                                # ✅ AUDIT: Obtener nombre de usuario para notificación
                                user_info = db.execute_query(
                                    "SELECT username, first_name FROM users WHERE id = %s", (user_id,)
                                )
                                uname = "Desconocido"
                                if user_info:
                                    uname = user_info[0].get('username') or user_info[0].get('first_name') or f"ID_{user_id}"

                                # ✅ AUDIT: Notificar a admins sobre código encontrado
                                notify_search_activity(
                                    user_id=user_id,
                                    username=uname,
                                    email=email_addr,
                                    source=str(source),
                                    service='disney',
                                    found=True,
                                    code=code,
                                    code_type=code_type
                                )

                                return result
                                
                        except re.error as e:
                            logger.error(f"Error en regex {pattern_name}: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Error procesando patrón {pattern_name}: {e}")
                            continue
                
                except Exception as e:
                    logger.error(f"Error procesando mensaje {msg_id}: {e}")
                    continue
            
            # Si no se encontró código, no hay search_id → no hay verificación anti-fraude que programar.
            # Solo limpiar el registro de búsqueda activa si el usuario lo tenía registrado (sin /ex).
            logger.info(f"❌ No se encontró código Disney para {email_addr}")
            if not skip_verification:
                db.end_search_request(user_id)

            # ✅ AUDIT: Notificar a admins sobre búsqueda sin resultado
            user_info = db.execute_query(
                "SELECT username, first_name FROM users WHERE id = %s", (user_id,)
            )
            uname = "Desconocido"
            if user_info:
                uname = user_info[0].get('username') or user_info[0].get('first_name') or f"ID_{user_id}"
            notify_search_activity(
                user_id=user_id, username=uname, email=email_addr,
                source=str(source), service='disney', found=False
            )

            return {'found': False, 'email': email_addr}

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error en búsqueda Disney para {email_addr}: {e}")

            # ✅ CORRECCIÓN CRÍTICA: NO eliminar búsqueda activa si el error es por validación
            # Solo eliminar si es un error real de búsqueda (no de validación de permisos)
            should_end_search = False

            # Errores que requieren finalizar búsqueda:
            if "configuración IMAP" in error_msg or "Error conectando IMAP" in error_msg:
                should_end_search = True
                logger.info(f"🔓 Finalizando búsqueda por error de configuración IMAP")

            # ✅ NO finalizar búsqueda si:
            # - Es error de validación (BÚSQUEDA EN VERIFICACIÓN, Usuario bloqueado, etc.)
            # - Es error de timezone/comparación
            # - Es error de permisos
            if "BÚSQUEDA EN VERIFICACIÓN" in error_msg:
                logger.info(f"🔒 Búsqueda activa mantenida - usuario intentando buscar durante verificación")
            elif "Usuario bloqueado" in error_msg:
                logger.info(f"🔒 Búsqueda activa mantenida - usuario bloqueado intentando buscar")
            elif should_end_search:
                db.end_search_request(user_id)

            raise Exception(f"Error en búsqueda: {error_msg}")
        finally:
            if conn:
                try:
                    conn.logout()
                except:
                    pass
    
    def decode_subject(self, subject):
        """Decodifica el asunto del email"""
        if not subject:
            return ""
        
        try:
            decoded_parts = decode_header(subject)
            decoded_subject = ""
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        try:
                            decoded_subject += part.decode(encoding, 'ignore')
                        except (UnicodeDecodeError, LookupError):
                            decoded_subject += part.decode('utf-8', 'ignore')
                    else:
                        decoded_subject += part.decode('utf-8', 'ignore')
                else:
                    decoded_subject += str(part)
            
            return decoded_subject
        except Exception as e:
            logger.error(f"Error decodificando subject: {e}")
            return str(subject)
    
    def extract_body(self, email_message):
        """Extrae el cuerpo del mensaje"""
        body = ""
        
        try:
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    if content_type in ["text/html", "text/plain"]:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body += payload.decode('utf-8', 'ignore')
                        except Exception as e:
                            logger.error(f"Error extrayendo parte del mensaje: {e}")
                            continue
            else:
                try:
                    payload = email_message.get_payload(decode=True)
                    if payload:
                        body = payload.decode('utf-8', 'ignore')
                except Exception as e:
                    logger.error(f"Error extrayendo cuerpo del mensaje: {e}")
            
            return body
        except Exception as e:
            logger.error(f"Error general extrayendo cuerpo: {e}")
            return ""
    
    def determine_code_type(self, pattern_name, subject, from_addr):
        """Determina el tipo de código Disney basado en el patrón y contexto"""
        type_mapping = {
            'disney_code': 'Disney Plus Code',
            'disney_household': 'Disney Household Code', 
            'disney_mydisney': 'My Disney OTP'
        }
        
        return type_mapping.get(pattern_name, 'Disney Code')
    
    def save_search_result(self, user_id, email, result_type, result_code):
        """Guarda el resultado de búsqueda en la BD"""
        try:
            # CORREGIDO: Usar query específica para INSERT RETURNING en PostgreSQL
            conn = None
            cursor = None
            
            try:
                conn = db.get_connection()
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO disney_searches (user_id, email, result_type, result_code, verification_scheduled)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                """, (user_id, email, result_type, result_code, True))
                
                result = cursor.fetchone()
                conn.commit()
                
                if result:
                    search_id = result['id']
                    logger.info(f"✅ Búsqueda guardada con ID: {search_id}")
                    return search_id
                
                return None
                
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    db.put_connection(conn)
            
        except Exception as e:
            logger.error(f"Error guardando resultado de búsqueda: {e}")
            return None
    
    def schedule_email_verification(self, search_id, user_id, email_addr, original_code):
        """Programa verificación de cambio de email después de 6 minutos.
        ✅ AUDIT: Usa asyncio.create_task en vez de threading.Thread.
        """
        try:
            # Guardar verificación programada
            db.execute_query("""
                INSERT INTO email_change_verifications (search_id, user_id, email, original_code)
                VALUES (%s, %s, %s, %s)
            """, (search_id, user_id, email_addr, original_code))

            task_key = f"{user_id}_{email_addr}_{int(time.time())}"

            # Detectar si hay un event loop activo
            try:
                loop = asyncio.get_running_loop()
                # Hay loop activo → crear task directamente
                task = asyncio.ensure_future(
                    self._async_verify_email_change(
                        search_id, user_id, email_addr, original_code, task_key
                    )
                )
                self._verification_tasks[task_key] = task
                logger.info(f"✅ Verificación async programada para {email_addr} en {VERIFICATION_DELAY_SECONDS//60} minutos (key: {task_key})")
            except RuntimeError:
                # No hay loop activo (llamado desde thread del executor)
                # Programar en el loop principal
                import concurrent.futures
                logger.info(f"✅ Verificación programada vía thread fallback para {email_addr} (key: {task_key})")
                import threading
                t = threading.Thread(
                    target=self._run_async_verification,
                    args=(search_id, user_id, email_addr, original_code, task_key),
                    daemon=True
                )
                t.start()

        except Exception as e:
            logger.error(f"❌ Error programando verificación: {e}")

    def _run_async_verification(self, search_id, user_id, email_addr, original_code, task_key):
        """Ejecuta la verificación async desde un thread sin event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(
                self._async_verify_email_change(
                    search_id, user_id, email_addr, original_code, task_key
                )
            )
            loop.close()
        except Exception as e:
            logger.error(f"❌ Error en verificación async fallback: {e}")

    async def _async_verify_email_change(self, search_id, user_id, email_addr, original_code, task_key):
        """✅ AUDIT: Verificación async — no bloquea threads del OS.
        Usa asyncio.sleep para la espera + run_in_executor para IMAP.
        """
        try:
            # ✅ asyncio.sleep no bloquea threads
            await asyncio.sleep(VERIFICATION_DELAY_SECONDS)

            # Ejecutar operación IMAP bloqueante en thread pool
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,  # ThreadPoolExecutor por defecto
                self._sync_verify_email_change,
                search_id, user_id, email_addr, original_code
            )
        except asyncio.CancelledError:
            logger.info(f"🛑 Verificación cancelada para {email_addr}")
        except Exception as e:
            logger.error(f"❌ Error en verificación async: {e}")
            self.mark_verification_completed(search_id, False, user_id)
        finally:
            # Limpiar referencia al task
            self._verification_tasks.pop(task_key, None)
            logger.debug(f"🧹 Task de verificación eliminado del registro: {task_key}")
    
    def _sync_verify_email_change(self, search_id, user_id, email_addr, original_code):
        """Verifica si hubo cambio de email (lógica IMAP pura, bloqueante).
        ✅ AUDIT: Extraido de verify_email_change para ejecutar vía run_in_executor.
        """
        conn = None
        try:
            logger.info(f"🔍 Verificando cambio de email para {email_addr}")
            
            # Conectar a email
            config = self.get_imap_config(email_addr)
            conn = self.connect_imap(config)
            
            # Buscar emails de los últimos 2 minutos
            date_since = (datetime.now() - timedelta(minutes=2)).strftime("%d-%b-%Y")
            
            # Buscar emails Disney
            search_criteria = []
            for from_addr in DISNEY_FROM_ADDRESSES:
                search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')
            
            combined_criteria = f'OR {" ".join(search_criteria)}' if len(search_criteria) > 1 else search_criteria[0]
            
            status, messages = conn.search(None, combined_criteria)
            
            if not messages[0]:
                logger.info(f"✅ No se encontraron nuevos emails para {email_addr}")
                self.mark_verification_completed(search_id, False, user_id)
                return
            
            # Procesar mensajes recientes
            message_ids = messages[0].split()
            message_ids.reverse()
            
            email_changed = False
            
            for msg_id in message_ids[:5]:  # Solo los 5 más recientes
                try:
                    status, msg_data = conn.fetch(msg_id, '(RFC822)')
                    if not msg_data or not msg_data[0] or not msg_data[0][1]:
                        continue
                        
                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    
                    # Extraer cuerpo del mensaje
                    body = self.extract_body(email_message)
                    
                    if not body:
                        continue
                    
                    # Verificar patrones de cambio de email
                    for pattern in self.email_change_patterns:
                        try:
                            regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                            if regex.search(body):
                                email_changed = True
                                logger.warning(f"⚠️ Detectado cambio de email en {email_addr}")
                                break
                        except re.error as e:
                            logger.error(f"Error en regex de cambio: {e}")
                            continue
                    
                    if email_changed:
                        break
                        
                except Exception as e:
                    logger.error(f"Error procesando mensaje de verificación: {e}")
                    continue
            
            if email_changed:
                # Bloquear usuario
                reason = f"Cambio de email detectado en {email_addr}"
                db.block_user(user_id, reason, email_addr)

                # Marcar verificación como completada
                self.mark_verification_completed(search_id, True, user_id)

                # Notificar a todos los administradores
                self.notify_admins_email_change(user_id, email_addr, original_code)

                logger.warning(f"🚨 Usuario {user_id} bloqueado por cambio de email en {email_addr}")
            else:
                logger.info(f"✅ No se detectó cambio de email para {email_addr}")
                self.mark_verification_completed(search_id, False, user_id)
                
        except Exception as e:
            logger.error(f"❌ Error verificando cambio de email: {e}")
            self.mark_verification_completed(search_id, False, user_id)
        finally:
            if conn is not None:
                try:
                    conn.logout()
                except Exception as logout_err:
                    logger.debug(f"⚠️ Error cerrando conexión IMAP en verificación: {logout_err}")
    
    def mark_verification_completed(self, search_id, email_changed, user_id):
        """Marca la verificación como completada y finaliza la búsqueda activa"""
        try:
            db.execute_query("""
                UPDATE email_change_verifications
                SET verified_at = CURRENT_TIMESTAMP, email_changed = %s
                WHERE search_id = %s
            """, (email_changed, search_id))

            db.execute_query("""
                UPDATE disney_searches
                SET verification_completed = TRUE
                WHERE id = %s
            """, (search_id,))

            # ✅ NUEVO: Finalizar búsqueda activa después de completar verificación
            db.end_search_request(user_id)
            logger.info(f"✅ Verificación completada y búsqueda finalizada para usuario {user_id}")

        except Exception as e:
            logger.error(f"❌ Error marcando verificación completada: {e}")
    
    def notify_admins_email_change(self, user_id, email_addr, original_code):
        """Notifica SOLO a los super administradores sobre cambio de email por Telegram"""
        try:
            # Obtener información del usuario
            user_info = db.execute_query(
                "SELECT username, first_name FROM users WHERE id = %s",
                (user_id,)
            )
            
            username = "Usuario desconocido"
            if user_info:
                username = user_info[0]['username'] or user_info[0]['first_name'] or f"ID_{user_id}"
            
            # ACTUALIZADO: Usar importación diferida y threading para evitar problemas con asyncio
            def send_notification_thread():
                try:
                    # Importar bot en el thread para evitar problemas de import circular
                    from telegram_bot import bot
                    import asyncio
                    
                    # Crear mensaje sin Markdown para evitar errores de parsing
                    message = (
                        "🚨 ALERTA DE SEGURIDAD\n\n"
                        "⚠️ Usuario bloqueado por cambio de email\n\n"
                        f"👤 Usuario: {username}\n"
                        f"🆔 ID: {user_id}\n"
                        f"📧 Email: {email_addr}\n"
                        f"🏰 Código original: {original_code}\n"
                        f"🕐 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                        "✅ El usuario ha sido bloqueado automáticamente"
                    )
                    
                    # Función async para enviar el mensaje a todos los super admins
                    async def send_messages():
                        try:
                            # Intentar enviar mensaje si el bot está disponible
                            if hasattr(bot, 'app') and bot.app and hasattr(bot.app, 'bot'):
                                
                                # ACTUALIZADO: Enviar SOLO a super administradores
                                successful_sends = 0
                                for admin_id in SUPER_ADMIN_IDS:
                                    try:
                                        await bot.app.bot.send_message(
                                            chat_id=admin_id,
                                            text=message,
                                            parse_mode=None  # Sin formato para evitar errores
                                        )
                                        successful_sends += 1
                                        logger.info(f"✅ Notificación enviada al super admin {admin_id}")
                                    except Exception as e:
                                        logger.error(f"❌ Error enviando notificación al super admin {admin_id}: {e}")
                                
                                if successful_sends > 0:
                                    logger.info(f"✅ Notificación enviada a {successful_sends}/{len(SUPER_ADMIN_IDS)} super admins sobre bloqueo de usuario {user_id}")
                                else:
                                    logger.warning(f"⚠️ No se pudo enviar notificaciones a ningún super admin - Usuario {user_id} bloqueado")
                            else:
                                logger.warning(f"⚠️ Bot no disponible para notificación - Usuario {user_id} bloqueado")
                        except Exception as e:
                            logger.error(f"❌ Error enviando notificación a super admins: {e}")
                    
                    # Ejecutar la notificación
                    try:
                        # Crear un nuevo loop para este thread
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(send_messages())
                        loop.close()
                    except Exception as e:
                        logger.error(f"❌ Error ejecutando notificación async: {e}")
                        
                except Exception as e:
                    logger.error(f"❌ Error en thread de notificación: {e}")
            
            # Ejecutar en un thread separado para evitar problemas con asyncio
            notification_thread = threading.Thread(
                target=send_notification_thread,
                daemon=True
            )
            notification_thread.start()
            
            # Log para depuración - ACTUALIZADO: Especificar que va solo a super admins
            logger.warning(f"🚨 NOTIFICACIÓN SUPER ADMINS: Usuario {username} ({user_id}) bloqueado por cambio de email en {email_addr}. Código original: {original_code} - Solo notificado a super administradores")
            
        except Exception as e:
            logger.error(f"❌ Error notificando a los super administradores: {e}")

    def search_service_codes(self, email_addr, user_id, service, sub_option, source=SearchSource.WEB):
        """Busca códigos/links de servicios NO-Disney (Crunchyroll, Max, Prime)

        Sin verificación de 6 minutos, sin detección de cambio de email.
        Solo busca el patrón regex específico de la sub-opción seleccionada.

        Args:
            email_addr: Email donde buscar
            user_id: ID del usuario que solicita
            service: Clave del servicio ('crunchyroll', 'max', 'prime')
            sub_option: Clave de la sub-opción ('crunchyroll_reset', 'max_code', etc.)
            source: Origen de la solicitud ('web')
        """
        conn = None
        try:
            # Validar que el servicio existe
            service_cfg = SERVICE_CONFIG.get(service)
            if not service_cfg:
                raise Exception(f"Servicio no reconocido: {service}")

            # Validar que la sub-opción existe
            sub_opt_cfg = service_cfg['sub_options'].get(sub_option)
            if not sub_opt_cfg:
                raise Exception(f"Opción no reconocida: {sub_option}")

            # Verificar si el usuario está bloqueado
            user_status = db.execute_query(
                "SELECT is_blocked, blocked_reason FROM users WHERE id = %s",
                (user_id,)
            )

            if user_status and user_status[0]['is_blocked']:
                reason = user_status[0]['blocked_reason'] or "Usuario bloqueado"
                raise Exception(f"Usuario bloqueado: {reason}")

            # Conectar a IMAP
            config = self.get_imap_config(email_addr)
            conn = self.connect_imap(config)

            # Buscar emails de los últimos 2 días
            date_since = (datetime.now() - timedelta(days=2)).strftime("%d-%b-%Y")

            # Construir criterio de búsqueda con from_addresses del servicio
            from_addresses = service_cfg['from_addresses']
            search_criteria = []
            for from_addr in from_addresses:
                search_criteria.append(f'(FROM "{from_addr}" TO "{email_addr}" SINCE {date_since})')

            combined_criteria = f'OR {" ".join(search_criteria)}' if len(search_criteria) > 1 else search_criteria[0]

            # Buscar mensajes
            status, messages = conn.search(None, combined_criteria)

            if not messages[0]:
                logger.info(f"No se encontraron emails de {service_cfg['name']} para {email_addr}")
                return {'found': False, 'email': email_addr}

            # Procesar mensajes (más recientes primero)
            message_ids = messages[0].split()
            message_ids.reverse()

            # Patrón regex de la sub-opción seleccionada
            pattern = sub_opt_cfg['pattern']

            for msg_id in message_ids[:10]:
                try:
                    status, msg_data = conn.fetch(msg_id, '(RFC822)')
                    if not msg_data or not msg_data[0] or not msg_data[0][1]:
                        continue

                    raw_email = msg_data[0][1]
                    email_message = email.message_from_bytes(raw_email)

                    subject = self.decode_subject(email_message.get('Subject', ''))
                    from_addr = email_message.get('From', '')
                    date_str = email_message.get('Date', '')

                    body = self.extract_body(email_message)

                    if not body:
                        continue

                    try:
                        regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                        match = regex.search(body)

                        if match:
                            code = match.group(1) if match.groups() else match.group(0)
                            code = code.strip()

                            if not code:
                                continue

                            result = {
                                'found': True,
                                'code': code,
                                'type': f"{service_cfg['name']} - {sub_opt_cfg['label']}",
                                'email': email_addr,
                                'subject': subject,
                                'date': date_str,
                                'pattern_used': sub_option
                            }

                            # Guardar búsqueda en BD (sin verificación de cambio de email)
                            self.save_search_result(user_id, email_addr, result['type'], code)

                            logger.info(f"✅ {service_cfg['name']} resultado encontrado para {email_addr}: {sub_opt_cfg['label']}")

                            # ✅ AUDIT: Notificar a admins sobre código de servicio encontrado
                            user_info = db.execute_query(
                                "SELECT username, first_name FROM users WHERE id = %s", (user_id,)
                            )
                            uname = "Desconocido"
                            if user_info:
                                uname = user_info[0].get('username') or user_info[0].get('first_name') or f"ID_{user_id}"
                            notify_search_activity(
                                user_id=user_id, username=uname, email=email_addr,
                                source=str(source), service=service,
                                found=True, code=code,
                                code_type=result['type'], sub_option=sub_option
                            )

                            return result

                    except re.error as e:
                        logger.error(f"Error en regex {sub_option}: {e}")
                        continue

                except Exception as e:
                    logger.error(f"Error procesando mensaje {msg_id} para {service}: {e}")
                    continue

            logger.info(f"❌ No se encontró resultado de {service_cfg['name']} para {email_addr}")

            # ✅ AUDIT: Notificar a admins sobre búsqueda de servicio sin resultado
            user_info = db.execute_query(
                "SELECT username, first_name FROM users WHERE id = %s", (user_id,)
            )
            uname = "Desconocido"
            if user_info:
                uname = user_info[0].get('username') or user_info[0].get('first_name') or f"ID_{user_id}"
            notify_search_activity(
                user_id=user_id, username=uname, email=email_addr,
                source=str(source), service=service,
                found=False, sub_option=sub_option
            )

            return {'found': False, 'email': email_addr}

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error en búsqueda {service} para {email_addr}: {e}")
            raise Exception(f"Error en búsqueda: {error_msg}")
        finally:
            if conn:
                try:
                    conn.logout()
                except:
                    pass

# Instancia global
disney_searcher = DisneySearcher()
