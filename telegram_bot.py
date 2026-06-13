import logging
import asyncio
import os
import zipfile
import re
import tempfile
import shutil
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes
from telegram.helpers import escape_markdown
from telegram.error import NetworkError, TimedOut, RetryAfter
from config import BOT_TOKEN, SUPER_ADMIN_IDS, DISNEY_PATTERNS, SERVICE_CONFIG, is_super_admin, get_primary_super_admin
from database import db
from disney_search import disney_searcher
from permissions import can_use_email
from enums import SearchSource

logger = logging.getLogger(__name__)

class DisneyBot:
    def __init__(self):
        self.app = Application.builder().token(BOT_TOKEN).build()
        self.setup_handlers()
        self.restart_count = 0
        self.max_restarts = 10
        self.shutdown_event = None
    
    def setup_handlers(self):
        """Configura los manejadores de comandos"""
        # Comandos principales
        self.app.add_handler(CommandHandler("start", self.start_command))
        self.app.add_handler(CommandHandler("add", self.add_command))
        self.app.add_handler(CommandHandler("del", self.del_command))
        self.app.add_handler(CommandHandler("list", self.list_command))
        self.app.add_handler(CommandHandler("addimap", self.addimap_command))
        self.app.add_handler(CommandHandler("delimap", self.delimap_command))
        self.app.add_handler(CommandHandler("deluser", self.deluser_command))
        self.app.add_handler(CommandHandler("check", self.check_command))
        self.app.add_handler(CommandHandler("addadmin", self.addadmin_command))
        self.app.add_handler(CommandHandler("deladmin", self.deladmin_command))
        self.app.add_handler(CommandHandler("unblock", self.unblock_command))
        self.app.add_handler(CommandHandler("blocked", self.blocked_command))
        self.app.add_handler(CommandHandler("addtime", self.addtime_command))
        self.app.add_handler(CommandHandler("ex", self.exclude_command))
        self.app.add_handler(CommandHandler("msg", self.msg_command))

        # Callbacks de botones inline (/check multi-servicio)
        self.app.add_handler(CallbackQueryHandler(self.handle_service_callback,    pattern=r'^svc:'))
        self.app.add_handler(CallbackQueryHandler(self.handle_suboption_callback,  pattern=r'^sub:'))
        
        # Manejador de mensajes de texto
        self.app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message))
        
        # Manejador de errores
        self.app.add_error_handler(self.error_handler)
    
    async def error_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Maneja errores del bot"""
        logger.error(f"Bot error: {context.error}")
        
        if isinstance(context.error, NetworkError):
            logger.warning("Error de red, reintentando...")
            await asyncio.sleep(5)
        elif isinstance(context.error, TimedOut):
            logger.warning("Timeout, reintentando...")
            await asyncio.sleep(3)
        elif isinstance(context.error, RetryAfter):
            logger.warning(f"Rate limit, esperando {context.error.retry_after} segundos")
            await asyncio.sleep(context.error.retry_after)
    
    async def check_super_admin_only(self, update: Update) -> bool:
        """Verifica si el usuario es SOLO super administrador"""
        user_id = update.effective_user.id
        
        if not is_super_admin(user_id):
            is_group = update.effective_chat and update.effective_chat.type in ("group", "supergroup")
            is_private = update.effective_chat and update.effective_chat.type == "private"
            
            if is_private and update.message:
                await update.message.reply_text("❌ Este comando está restringido solo a super administradores")
            return False
        
        return True

    async def check_admin_permissions(self, update: Update) -> bool:
        """Verifica si el usuario tiene permisos de administrador (super admin o admin normal)"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            return True
        
        admin_data = db.execute_query(
            "SELECT is_admin FROM users WHERE id = %s AND is_admin = TRUE",
            (user_id,)
        )
        
        if not admin_data:
            is_group = update.effective_chat and update.effective_chat.type in ("group", "supergroup")
            is_private = update.effective_chat and update.effective_chat.type == "private"
            
            if is_private and update.message:
                await update.message.reply_text("❌ Este comando requiere permisos de administrador")
            return False
        
        return True

    async def can_use_email_restricted(self, user_id: int, email: str) -> bool:
        """✅ AUDIT: Delegado al módulo unificado permissions.py (DRY)"""
        # Obtener datos del usuario para determinar tipo
        is_super = is_super_admin(user_id)
        if is_super:
            return can_use_email(user_id, email, is_super=True)

        user_data = db.execute_query(
            "SELECT is_admin, free_access FROM users WHERE id = %s",
            (user_id,)
        )

        is_admin_user = bool(user_data and user_data[0].get('is_admin'))
        free_access = bool(user_data and user_data[0].get('free_access'))

        return can_use_email(
            user_id, email,
            is_admin=is_admin_user,
            is_super=False,
            free_access=free_access
        )
    
    def safe_format_message(self, message: str) -> str:
        """Formatea un mensaje de forma segura eliminando caracteres problemáticos de Markdown"""
        # Remover caracteres problemáticos para Markdown
        safe_message = message.replace('*', '').replace('_', '').replace('`', '').replace('[', '').replace(']', '')
        return safe_message
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /start"""
        user = update.effective_user
        user_id = user.id
        
        # Verificar si es super admin
        if is_super_admin(user_id):
            await self.send_admin_welcome(update)
            return
        
        # Verificar si el usuario está autorizado
        user_data = db.execute_query(
            "SELECT id, username, first_name, is_admin, free_access, expires_at, is_active, is_blocked, blocked_reason FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            # Usuario no autorizado - notificar a todos los super admins
            await self.notify_new_user(context, user)
            await update.message.reply_text(
                "❌ No estás autorizado para usar este bot.\n"
                "📧 Contacta al administrador para obtener acceso.\n\n"
                "🚨 ¡Aviso importante!\n"
                "A partir de ahora, puedes comunicarte con nosotros únicamente a través del nuevo número via Whatsapp:\n\n"
                "📞 +573022332535"
            )
            return
        
        user_info = user_data[0]
        
        # Verificar si está bloqueado
        if user_info['is_blocked']:
            reason = user_info['blocked_reason'] or "Usuario bloqueado"
            await update.message.reply_text(f"🚫 Tu cuenta está bloqueada: {reason}")
            return
        
        # Verificar si está activo y no expirado
        if not user_info['is_active']:
            await update.message.reply_text("❌ Tu cuenta está desactivada.")
            return
        
        if user_info['expires_at'] and datetime.now() > user_info['expires_at']:
            await update.message.reply_text("⏰ Tu acceso ha expirado. Contacta al administrador.")
            return
        
        # Enviar bienvenida personalizada
        await self.send_user_welcome(update, user_info)
    
    async def send_admin_welcome(self, update: Update):
        """Mensaje de bienvenida diferenciado para Super Admin vs Admin - SIN MARKDOWN"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            # Mensaje para Super Administrador - SIN MARKDOWN
            message = (
                "👑 BIENVENIDO SUPER ADMINISTRADOR\n\n"
                "🔧 COMANDOS DE SUPER ADMIN:\n"
                "• /add <user_id> <email1> [email2...] - Añadir cualquier email a usuario\n"
                "• /del <user_id> <email1> [email2...] - Eliminar cualquier email\n"
                "• /list [user_id] - Listar usuarios/emails\n"
                "• /addimap <domain> <email> <password> <server> - Configurar IMAP\n"
                "• /delimap <domain> - Eliminar config IMAP\n"
                "• /deluser <user_id> - Eliminar usuario\n"
                "• /addtime <user_id> <tiempo> - Agregar tiempo (ej: 30d)\n"
                "• /addadmin <user_id> <email1> [email2...] - Agregar admin con emails específicos\n"
                "• /deladmin <user_id> - Quitar administrador\n"
                "• /unblock <user_id> - Desbloquear usuario\n"
                "• /blocked - Listar usuarios bloqueados\n"
                "• /ex <user_id> - Excluir/incluir usuario de verificación de 6 min\n"
                "• /check <email> - Buscar códigos Disney (cualquier email)\n\n"
                "🏰 ACCESO TOTAL AL SISTEMA\n"
                "⚠️ RECIBES NOTIFICACIONES DE SEGURIDAD"
            )
        else:
            # Obtener emails asignados al admin
            admin_emails = db.execute_query(
                "SELECT email FROM user_emails WHERE user_id = %s",
                (user_id,)
            )
            
            email_count = len(admin_emails) if admin_emails else 0
            
            # Mensaje para Administrador normal - SIN MARKDOWN
            message = (
                "🛡️ BIENVENIDO ADMINISTRADOR\n\n"
                f"📧 TIENES {email_count} EMAILS ASIGNADOS\n\n"
                "🔧 COMANDOS DISPONIBLES:\n"
                "• /add <user_id> <email> - Compartir tus emails con usuarios (mantienes acceso)\n"
                "• /del <user_id> <email> - Eliminar emails (solo tus emails asignados)\n"
                "• /list [user_id] - Listar usuarios/emails\n"
                "• /deluser <user_id> - Eliminar usuario\n"
                "• /addtime <user_id> <tiempo> - Agregar tiempo a usuarios (ej: 30d)\n"
                "• /check <email> - Buscar códigos Disney (solo tus emails asignados)\n\n"
                "🤝 CAPACIDAD DE GESTIÓN:\n"
                "• Solo puedes gestionar emails de tu lista asignada\n"
                "• Al asignar un email tuyo, TÚ SIEMPRE mantienes acceso\n"
                "• Si el email ya está en uso, se lo quitas al usuario anterior\n"
                "• Resultado: tú y el nuevo usuario comparten el email\n\n"
                "📧 RESTRICCIÓN IMPORTANTE:\n"
                "• Solo puedes usar emails de tu lista asignada\n"
                "• Tu cuenta será bloqueada si cambias emails durante búsquedas\n\n"
                "🚫 NO DISPONIBLE PARA TI:\n"
                "• Configuración IMAP\n"
                "• Gestión de administradores\n"
                "• Gestión de usuarios bloqueados\n"
                "• Transferencia completa de emails (solo compartir)"
            )
        
        await update.message.reply_text(message)  # SIN parse_mode
    
    async def send_user_welcome(self, update: Update, user_info):
        """Mensaje de bienvenida para usuario normal - SIN MARKDOWN"""
        username = user_info['username'] or user_info['first_name'] or "Usuario"
        
        # Obtener emails asignados
        emails = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s",
            (user_info['id'],)
        )
        
        email_count = len(emails) if emails else 0
        
        # Calcular días restantes
        days_left = "∞"
        if user_info['expires_at']:
            time_left = user_info['expires_at'] - datetime.now()
            days_left = max(0, time_left.days)
        
        message = (
            f"🎉 BIENVENIDO {username}!\n\n"
            f"📊 TU INFORMACIÓN:\n"
            f"📧 Emails asignados: {email_count}\n"
            f"⏰ Días restantes: {days_left}\n"
            f"🔓 Acceso libre: {'Sí' if user_info['free_access'] else 'No'}\n\n"
            f"🏰 COMANDOS DISPONIBLES:\n"
            f"• /check <email> - Buscar códigos Disney\n"
            f"• /add <user_id> <email> - Agregar email\n"
            f"• /del <user_id> <email> - Eliminar email\n\n"
            f"💡 USO: Envía /check tu@email.com para buscar códigos Disney\n"
            f"📧 RESTRICCIÓN: Solo puedes usar emails asignados a ti.\n"
            f"⚠️ IMPORTANTE: No cambies emails durante búsquedas."
        )
        
        await update.message.reply_text(message)  # SIN parse_mode
    
    async def notify_new_user(self, context: ContextTypes.DEFAULT_TYPE, user):
        """Notifica a todos los super admins sobre nuevo usuario - SIN MARKDOWN"""
        try:
            username = user.username if user.username else 'No establecido'
            name = user.full_name
            
            message = (
                "🆕 NUEVO USUARIO DETECTADO\n\n"
                f"🆔 ID: {user.id}\n"
                f"👤 Nombre: {name}\n"
                f"🔖 Username: @{username}\n"
                f"📅 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
            
            # Enviar a todos los super admins
            for admin_id in SUPER_ADMIN_IDS:
                try:
                    await context.bot.send_message(
                        chat_id=admin_id,
                        text=message
                    )
                except Exception as e:
                    logger.error(f"Error notificando a super admin {admin_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Error notificando nuevo usuario: {e}")
    
    async def addtime_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ ACTUALIZADO: /addtime <user_id> <tiempo> - AHORA PARA ADMINISTRADORES TAMBIÉN"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) != 2:
            await update.message.reply_text(
                "❌ Uso: /addtime <user_id> <tiempo>\n\n"
                "📅 Ejemplos:\n"
                "• /addtime 123456789 30d - Agregar 30 días\n"
                "• /addtime 987654321 7d - Agregar 7 días\n"
                "• /addtime 555555555 365d - Agregar 1 año\n\n"
                "⏰ El tiempo debe especificarse con 'd' para días"
            )
            return
        
        try:
            user_id = int(context.args[0])
            time_str = context.args[1].strip().lower()
            
            # Validar formato del tiempo (debe terminar en 'd')
            if not time_str.endswith('d'):
                await update.message.reply_text(
                    "❌ Formato de tiempo inválido. Debe terminar en 'd' para días.\n"
                    "📅 Ejemplo: 30d (30 días)"
                )
                return
            
            # Extraer número de días
            try:
                days_str = time_str[:-1]  # Quitar la 'd'
                days = int(days_str)
                
                if days <= 0:
                    await update.message.reply_text("❌ El número de días debe ser mayor a 0")
                    return
                
                if days > 3650:  # Máximo 10 años
                    await update.message.reply_text("❌ El máximo de días permitido es 3650 (10 años)")
                    return
                    
            except ValueError:
                await update.message.reply_text(
                    "❌ Formato de tiempo inválido. Debe ser un número seguido de 'd'.\n"
                    "📅 Ejemplo: 30d"
                )
                return
            
            # Verificar si el usuario existe
            user_data = db.execute_query(
                "SELECT id, username, first_name, expires_at, is_active FROM users WHERE id = %s",
                (user_id,)
            )
            
            current_time = datetime.now()
            new_expiry_time = current_time + timedelta(days=days)
            
            # Obtener información del admin que ejecuta el comando
            admin_id = update.effective_user.id
            admin_type = "Super Admin" if is_super_admin(admin_id) else "Administrador"
            
            if not user_data:
                # Usuario no existe - crear nuevo usuario con el tiempo especificado
                db.execute_query("""
                    INSERT INTO users (id, expires_at, is_active, created_at)
                    VALUES (%s, %s, %s, %s)
                """, (user_id, new_expiry_time, True, current_time))
                
                await update.message.reply_text(
                    f"✅ Usuario {user_id} creado exitosamente\n"
                    f"⏰ Tiempo asignado: {days} días\n"
                    f"📅 Expira: {new_expiry_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"👤 Creado por: {admin_type}"
                )
                
                logger.info(f"✅ Nuevo usuario {user_id} creado con {days} días por {admin_type} {admin_id}")
            else:
                # Usuario existe - agregar tiempo a su expiración actual
                user_info = user_data[0]
                current_expiry = user_info['expires_at']
                
                if current_expiry and current_expiry > current_time:
                    # Si aún no ha expirado, agregar días a la fecha actual de expiración
                    new_expiry_time = current_expiry + timedelta(days=days)
                    time_action = f"Tiempo agregado a fecha actual de expiración ({current_expiry.strftime('%Y-%m-%d')})"
                else:
                    # Si ya expiró o no tenía fecha, agregar días desde ahora
                    new_expiry_time = current_time + timedelta(days=days)
                    time_action = "Tiempo agregado desde ahora (usuario expirado o sin fecha)"
                
                # Actualizar en la base de datos
                db.execute_query("""
                    UPDATE users 
                    SET expires_at = %s, is_active = TRUE
                    WHERE id = %s
                """, (new_expiry_time, user_id))
                
                username = user_info['username'] or user_info['first_name'] or f"Usuario_{user_id}"
                
                await update.message.reply_text(
                    f"✅ Tiempo agregado a {username} (ID: {user_id})\n"
                    f"⏰ Días agregados: {days}\n"
                    f"📅 Nueva fecha de expiración: {new_expiry_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"ℹ️ {time_action}\n"
                    f"👤 Modificado por: {admin_type}"
                )
                
                logger.info(f"✅ {days} días agregados al usuario {user_id} por {admin_type} {admin_id}")
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            logger.error(f"Error en addtime_command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def unblock_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /unblock <user_id> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /unblock <user_id>")
            return
        
        try:
            user_id = int(context.args[0])
            
            # Desbloquear usuario
            result = db.execute_query("""
                UPDATE users 
                SET is_blocked = FALSE, blocked_reason = NULL, blocked_at = NULL
                WHERE id = %s
            """, (user_id,))
            
            if result > 0:
                await update.message.reply_text(f"✅ Usuario {user_id} desbloqueado correctamente")
            else:
                await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def blocked_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /blocked - Lista usuarios bloqueados - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        try:
            blocked_users = db.execute_query("""
                SELECT id, username, first_name, blocked_reason, blocked_at
                FROM users 
                WHERE is_blocked = TRUE
                ORDER BY blocked_at DESC
            """)
            
            if not blocked_users:
                await update.message.reply_text("📋 No hay usuarios bloqueados")
                return
            
            # Usar directorio temporal del sistema
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix='usuarios_bloqueados_', 
                                           encoding='utf-8', delete=False) as temp_file:
                temp_file.write("USUARIOS BLOQUEADOS\n")
                temp_file.write("=" * 50 + "\n\n")
                
                for user in blocked_users:
                    temp_file.write(f"ID: {user['id']}\n")
                    temp_file.write(f"Username: {user['username'] or 'No establecido'}\n")
                    temp_file.write(f"Nombre: {user['first_name'] or 'No establecido'}\n")
                    temp_file.write(f"Razón: {user['blocked_reason'] or 'Sin razón especificada'}\n")
                    temp_file.write(f"Bloqueado: {user['blocked_at']}\n")
                    temp_file.write("-" * 30 + "\n\n")
                
                temp_file.write(f"Total: {len(blocked_users)} usuarios bloqueados")
                temp_filename = temp_file.name
            
            # Enviar archivo temporal
            try:
                with open(temp_filename, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"usuarios_bloqueados_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        caption=f"🚫 Lista de {len(blocked_users)} usuarios bloqueados"
                    )
                logger.info(f"✅ Lista de usuarios bloqueados enviada correctamente ({len(blocked_users)} usuarios)")
            finally:
                # Limpiar archivo temporal
                try:
                    os.unlink(temp_filename)
                except OSError:
                    pass
            
        except Exception as e:
            logger.error(f"❌ Error en blocked_command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def msg_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /msg <texto> - Enviar mensaje a todos los usuarios (SOLO SUPER ADMIN)"""
        if not await self.check_super_admin_only(update):
            return

        # Obtener el mensaje original respetando saltos de línea
        full_text = update.message.text
        # Eliminar el comando '/msg' del inicio (4 caracteres + espacios)
        if full_text.startswith('/msg'):
            message_text = full_text[4:].strip()
        else:
            message_text = " ".join(context.args)

        if not message_text:
             await update.message.reply_text(
                "❌ Uso: /msg <texto del mensaje>\n"
                "📢 Envía un mensaje a TODOS los usuarios registrados."
            )
             return
        
        # Confirmación inicial
        status_msg = await update.message.reply_text("📢 Preparando difusión de mensaje...")
        
        try:
            # Obtener todos los usuarios activos y no bloqueados
            users = db.execute_query("SELECT id, first_name FROM users WHERE is_active = TRUE AND is_blocked = FALSE")
            
            if not users:
                await status_msg.edit_text("❌ No hay usuarios activos para enviar el mensaje.")
                return

            total_users = len(users)
            sent_count = 0
            failed_count = 0
            
            await status_msg.edit_text(f"📢 Iniciando envío a {total_users} usuarios...")
            
            for user in users:
                try:
                    user_id = user['id']
                    # No enviarse a sí mismo si es el admin que lo ejecuta (opcional, pero mejor feedback)
                    # if user_id == update.effective_user.id:
                    #     continue
                        
                    await context.bot.send_message(
                        chat_id=user_id,
                        text=f"📢 **ANUNCIO IMPORTANTE**\n\n{message_text}",
                        parse_mode="Markdown"
                    )
                    sent_count += 1
                    
                    # Pequeña pausa para evitar flood limits
                    if sent_count % 20 == 0:
                        await asyncio.sleep(1)
                        
                except Exception as e:
                    logger.warning(f"⚠️ Error enviando a {user['id']}: {e}")
                    failed_count += 1
            
            # Reporte final
            await status_msg.edit_text(
                f"✅ Difusión completada\n\n"
                f"📨 Enviados: {sent_count}\n"
                f"❌ Fallidos: {failed_count}\n"
                f"👥 Total intentados: {total_users}"
            )
            
            logger.info(f"📢 Difusión completada: {sent_count} enviados, {failed_count} fallidos")
            
        except Exception as e:
            logger.error(f"❌ Error en msg_command: {e}")
            await status_msg.edit_text(f"❌ Error crítico en difusión: {str(e)}")

    # ═══════════════════════════════════════════════════════════════
    # /check  — flujo multi-servicio con botones inline
    # ═══════════════════════════════════════════════════════════════

    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /check <email>. Muestra teclado de servicios."""
        user_id = update.effective_user.id

        if not await self.check_user_access(update):
            return

        if len(context.args) != 1:
            await update.message.reply_text(
                "Uso: /check <email>\n\n"
                "Ejemplo: /check usuario@gmail.com"
            )
            return

        email = context.args[0].strip().lower()

        if '@' not in email or '.' not in email.split('@')[1]:
            await update.message.reply_text("Formato de email invalido")
            return

        if not await self.can_use_email_restricted(user_id, email):
            await update.message.reply_text(
                "No tienes permiso para usar este email.\n"
                "Solo puedes usar emails asignados a tu cuenta."
            )
            return

        # ✅ Guardar email en user_data — NO en callback_data (limite 64 bytes)
        context.user_data['check_email'] = email

        services = [
            ("Disney",  "disney"),
            ("Max",     "max"),
            ("Netflix", "netflix"),
        ]

        buttons = [
            [InlineKeyboardButton(label, callback_data=f"svc:{key}")]
            for label, key in services
        ]
        keyboard = InlineKeyboardMarkup(buttons)

        await update.message.reply_text(
            f"Email: {email}\n\n"
            "Selecciona el servicio:",
            reply_markup=keyboard
        )

    # ─── Callback: usuario eligio un servicio ─────────────────────
    async def handle_service_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Callback pattern: svc:<service>"""
        query = update.callback_query
        await query.answer()

        _, service = query.data.split(':', 1)
        user_id = query.from_user.id

        # Recuperar email guardado
        email = context.user_data.get('check_email')
        if not email:
            await query.edit_message_text("Sesion expirada. Usa /check <email> de nuevo.")
            return

        # Boton de volver: mostrar menu de servicios de nuevo
        if service == '_back':
            services = [
                ("Disney",  "disney"),
                ("Max",     "max"),
                ("Netflix", "netflix"),
            ]
            buttons = [
                [InlineKeyboardButton(label, callback_data=f"svc:{key}")]
                for label, key in services
            ]
            await query.edit_message_text(
                f"Email: {email}\n\n"
                "Selecciona el servicio:",
                reply_markup=InlineKeyboardMarkup(buttons)
            )
            return

        # Verificar permisos
        if not await self.can_use_email_restricted(user_id, email):
            await query.edit_message_text("Ya no tienes permiso para usar este email.")
            return

        # Disney: buscar directo
        if service == 'disney':
            await query.edit_message_text(f"Buscando codigos Disney para {email}...")
            await self._run_disney_search(query, email, user_id)
            return

        # Otros servicios: mostrar sub-opciones
        svc_cfg = SERVICE_CONFIG.get(service)
        if not svc_cfg:
            await query.edit_message_text("Servicio no reconocido.")
            return

        sub_options = svc_cfg.get('sub_options', {})
        if not sub_options:
            await query.edit_message_text(f"Buscando en {svc_cfg['name']} para {email}...")
            first_key = list(sub_options.keys())[0]
            await self._run_service_search(query, email, user_id, service, first_key)
            return

        # Botones de sub-opciones — callback_data corto: sub:<key>:<service>
        buttons = [
            [InlineKeyboardButton(cfg['label'], callback_data=f"sub:{key}:{service}")]
            for key, cfg in sub_options.items()
        ]
        buttons.append([InlineKeyboardButton("Volver", callback_data="svc:_back")])
        keyboard = InlineKeyboardMarkup(buttons)

        await query.edit_message_text(
            f"{svc_cfg['name']} - {email}\n\n"
            "Selecciona el tipo de busqueda:",
            reply_markup=keyboard
        )

    # ─── Callback: usuario eligio una sub-opcion ──────────────────
    async def handle_suboption_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Callback pattern: sub:<sub_option>:<service>"""
        query = update.callback_query
        await query.answer()

        _, sub_option, service = query.data.split(':', 2)
        user_id = query.from_user.id

        # Recuperar email guardado
        email = context.user_data.get('check_email')
        if not email:
            await query.edit_message_text("Sesion expirada. Usa /check <email> de nuevo.")
            return

        svc_cfg = SERVICE_CONFIG.get(service, {})
        sub_cfg = svc_cfg.get('sub_options', {}).get(sub_option, {})
        label    = sub_cfg.get('label', sub_option)
        svc_name = svc_cfg.get('name', service)

        await query.edit_message_text(
            f"Buscando {svc_name} - {label}\n"
            f"Email: {email}..."
        )
        await self._run_service_search(query, email, user_id, service, sub_option)


    # ─── Helpers de búsqueda ──────────────────────────────────────
    async def _run_disney_search(self, query, email: str, user_id: int):
        """Ejecuta búsqueda Disney y edita el mensaje con el resultado."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, lambda: disney_searcher.search_disney_codes(email, user_id, source=SearchSource.TELEGRAM)
            )
            if result and result.get('found'):
                subj = result['subject']
                if len(subj) > 80:
                    subj = subj[:80] + "..."
                msg = (
                    "✅ CÓDIGO DISNEY ENCONTRADO\n\n"
                    f"🏰 Código: {result['code']}\n"
                    f"📧 Email: {result['email']}\n"
                    f"📝 Asunto: {subj}\n"
                    f"📅 Fecha: {result['date']}"
                )
            else:
                msg = (
                    "❌ NO SE ENCONTRARON CÓDIGOS DISNEY\n\n"
                    f"📧 Email: {email}\n"
                    f"📅 Período: Últimos 2 días\n"
                    f"🔍 Patrones probados: {len(DISNEY_PATTERNS)}"
                )
            await query.edit_message_text(msg)
        except Exception as e:
            logger.error(f"Error búsqueda Disney (bot): {e}")
            await query.edit_message_text(f"❌ Error en la búsqueda: {str(e)[:150]}")

    async def _run_service_search(self, query, email: str, user_id: int, service: str, sub_option: str):
        """Ejecuta búsqueda de cualquier servicio no-Disney y edita el mensaje."""
        try:
            svc_cfg  = SERVICE_CONFIG.get(service, {})
            sub_cfg  = svc_cfg.get('sub_options', {}).get(sub_option, {})
            svc_name = svc_cfg.get('name', service)
            label    = sub_cfg.get('label', sub_option)

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: disney_searcher.search_service_codes(
                    email, user_id, service, sub_option, source=SearchSource.TELEGRAM
                )
            )
            if result and result.get('found'):
                code = result['code']
                # Si el resultado es una URL larga, mostrar completo
                msg = (
                    f"✅ {svc_name.upper()} — {label}\n\n"
                    f"🔑 Resultado:\n{code}\n\n"
                    f"📧 Email: {result['email']}\n"
                    f"📅 Fecha: {result.get('date','')}"
                )
            else:
                msg = (
                    f"❌ Sin resultados — {svc_name} / {label}\n\n"
                    f"📧 Email: {email}\n"
                    f"📅 Período: Últimos 2 días"
                )
            await query.edit_message_text(msg)
        except Exception as e:
            logger.error(f"Error búsqueda {service}/{sub_option} (bot): {e}")
            await query.edit_message_text(f"❌ Error en la búsqueda: {str(e)[:150]}")

    
    async def check_user_access(self, update: Update) -> bool:
        """Verifica si el usuario tiene acceso al bot"""
        user_id = update.effective_user.id
        
        if is_super_admin(user_id):
            return True
            
        is_group = update.effective_chat and update.effective_chat.type in ("group", "supergroup")
        is_private = update.effective_chat and update.effective_chat.type == "private"
        
        user_data = db.execute_query(
            "SELECT is_active, expires_at, is_blocked, blocked_reason FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            if is_private and update.message:
                await update.message.reply_text("❌ No tienes acceso al bot")
            return False
        
        user_info = user_data[0]
        
        if user_info['is_blocked']:
            if is_private and update.message:
                reason = user_info['blocked_reason'] or "Usuario bloqueado"
                await update.message.reply_text(f"🚫 Tu cuenta está bloqueada: {reason}")
            return False
        
        if not user_info['is_active']:
            if is_private and update.message:
                await update.message.reply_text("❌ Tu cuenta está desactivada")
            return False
        
        if user_info['expires_at'] and datetime.now() > user_info['expires_at']:
            if is_private and update.message:
                await update.message.reply_text("⏰ Tu acceso ha expirado")
            return False
        
        return True
    
    async def add_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /add - TRANSFERENCIA SOLO PARA SUPER ADMIN"""
        if not await self.check_admin_permissions(update):
            return

        if len(context.args) < 2:
            await update.message.reply_text("❌ Uso: /add <user_id> <email1> [email2...]")
            return

        try:
            user_id = int(context.args[0])
            emails = context.args[1:]
            is_super_admin_user = is_super_admin(update.effective_user.id)

            # RESTRICCIÓN: Admins normales solo pueden gestionar emails de su lista asignada
            if not is_super_admin_user:
                # Obtener emails asignados al admin
                admin_emails = db.execute_query(
                    "SELECT email FROM user_emails WHERE user_id = %s",
                    (update.effective_user.id,)
                )

                if not admin_emails:
                    await update.message.reply_text(
                        "❌ No tienes emails asignados para gestionar.\n"
                        "📧 Solo puedes gestionar emails que tengas en tu lista asignada."
                    )
                    return

                admin_email_list = [row['email'] for row in admin_emails]

                # Verificar que todos los emails solicitados están en la lista del admin
                unauthorized_emails = [email for email in emails if email not in admin_email_list]

                if unauthorized_emails:
                    unauthorized_str = ", ".join(unauthorized_emails)
                    available_str = ", ".join(admin_email_list)
                    await update.message.reply_text(
                        f"❌ No puedes gestionar estos emails (no están en tu lista): {unauthorized_str}\n\n"
                        f"✅ Tus emails disponibles: {available_str}"
                    )
                    return

            # Verificar/crear usuario
            user_exists = db.execute_query("SELECT id FROM users WHERE id = %s", (user_id,))

            if not user_exists:
                # Crear usuario con 30 días de acceso
                expires_at = datetime.now() + timedelta(days=30)
                db.execute_query("""
                    INSERT INTO users (id, expires_at, is_active)
                    VALUES (%s, %s, %s)
                """, (user_id, expires_at, True))

            # ✅ NUEVA LÓGICA: Transferencia diferenciada por rol
            added_emails = []
            transferred_emails = []
            shared_emails = []
            blocked_emails = []

            for email in emails:
                try:
                    # Lógica de limpieza de asignaciones previas
                    if is_super_admin_user:
                        # ✅ SUPER ADMIN: Eliminar de TODOS los usuarios (Transferencia absoluta)
                        # El Super Admin siempre tiene acceso por código, no necesita fila en DB
                        deleted = db.execute_query("""
                            DELETE FROM user_emails WHERE email = %s
                        """, (email,))
                        
                        if deleted > 0:
                            logger.info(f"📧 Email {email} eliminado de {deleted} usuarios por Super Admin (Transferencia)")
                            transferred_emails.append(f"{email} (de {deleted} usuarios)")
                            
                    else:
                        # ✅ ADMIN NORMAL: Eliminar de TODOS EXCEPTO del Admin (Distribución)
                        # El Admin mantiene su copia, los demás la pierden
                        deleted = db.execute_query("""
                            DELETE FROM user_emails 
                            WHERE email = %s AND user_id != %s
                        """, (email, update.effective_user.id))
                        
                        if deleted > 0:
                            logger.info(f"📧 Email {email} revocado de {deleted} usuarios por Admin {update.effective_user.id} (Distribución)")
                            shared_emails.append(f"{email} (recuperado de {deleted} usuarios)")

                    # Asignar el email al nuevo usuario (siempre)
                    # Verificar si está bloqueado globalmente (opcional, aquí asumimos que si el admin lo tiene, es válido)
                    db.execute_query("""
                        INSERT INTO user_emails (user_id, email)
                        VALUES (%s, %s)
                        ON CONFLICT (user_id, email) DO NOTHING
                    """, (user_id, email))

                    added_emails.append(email)

                except Exception as e:
                    logger.error(f"Error procesando email {email}: {e}")

            # ✅ MENSAJE ACTUALIZADO con información completa
            message = f"✅ Usuario {user_id} actualizado\n📧 Emails procesados exitosamente: {len(added_emails)}"

            if added_emails:
                emails_text = "\n".join([f"• {email}" for email in added_emails])
                message += f"\n\nEMAILS ASIGNADOS:\n{emails_text}"

            if transferred_emails and is_super_admin_user:
                transferred_text = "\n".join([f"• {email}" for email in transferred_emails])
                message += f"\n\n🔄 EMAILS TRANSFERIDOS (Super Admin):\n{transferred_text}"
                message += f"\n💡 Los emails fueron movidos completamente al nuevo usuario"

            if shared_emails and not is_super_admin_user:
                shared_text = "\n".join([f"• {email}" for email in shared_emails])
                message += f"\n\n🤝 EMAILS GESTIONADOS (Admin):\n{shared_text}"
                message += f"\n💡 Mantienes acceso (están en tu lista) y ahora los comparte el usuario"

            if blocked_emails:
                blocked_text = "\n".join([f"• {email}" for email in blocked_emails])
                message += f"\n\n🚫 EMAILS BLOQUEADOS:\n{blocked_text}"
                if not is_super_admin_user:
                    message += f"\n\n⚠️ Solo puedes compartir emails que tengas asignados a ti"
                else:
                    message += f"\n\n⚠️ Emails ya asignados a otros usuarios"

            # Nota diferenciada por rol
            if not is_super_admin_user:
                message += f"\n\n🛡️ Como administrador puedes:\n• Gestionar solo emails de tu lista asignada\n• Quitar emails de otros usuarios si están en tu lista\n• Siempre mantener acceso a tus emails asignados"
            else:
                message += f"\n\n👑 Como super admin puedes:\n• Transferir cualquier email\n• Mover emails entre usuarios\n• Control total del sistema"

            await update.message.reply_text(message)

        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def del_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /del - SIN MARKDOWN PROBLEMÁTICO"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) < 2:
            await update.message.reply_text("❌ Uso: /del <user_id> <email1> [email2...]")
            return
        
        try:
            user_id = int(context.args[0])
            emails = context.args[1:]
            
            # RESTRICCIÓN: Admins normales solo pueden eliminar emails que ellos tienen asignados
            if not is_super_admin(update.effective_user.id):
                # Obtener emails asignados al admin
                admin_emails = db.execute_query(
                    "SELECT email FROM user_emails WHERE user_id = %s",
                    (update.effective_user.id,)
                )
                
                if not admin_emails:
                    await update.message.reply_text(
                        "❌ No tienes emails asignados para gestionar otros usuarios."
                    )
                    return
                
                admin_email_list = [row['email'] for row in admin_emails]
                
                # Verificar que todos los emails a eliminar están en los emails del admin
                unauthorized_emails = [email for email in emails if email not in admin_email_list]
                
                if unauthorized_emails:
                    unauthorized_str = ", ".join(unauthorized_emails)
                    available_str = ", ".join(admin_email_list)
                    await update.message.reply_text(
                        f"❌ No puedes eliminar estos emails (no los tienes asignados): {unauthorized_str}\n\n"
                        f"✅ Tus emails disponibles: {available_str}"
                    )
                    return
            
            deleted_count = 0
            for email in emails:
                result = db.execute_query("""
                    DELETE FROM user_emails 
                    WHERE user_id = %s AND email = %s
                """, (user_id, email))
                if result > 0:
                    deleted_count += 1
            
            message = f"✅ Se eliminaron {deleted_count} emails del usuario {user_id}"
            
            # Nota para admins normales - SIN asteriscos problemáticos
            if not is_super_admin(update.effective_user.id):
                message += f"\n\n🛡️ Eliminado como administrador - Solo emails asignados a ti"
            
            await update.message.reply_text(message)  # SIN parse_mode
            
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def list_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /list [user_id]"""
        if not await self.check_admin_permissions(update):
            return
        
        try:
            if context.args:
                # Listar emails de un usuario específico
                user_id = int(context.args[0])
                await self.list_user_emails(update, user_id)
            else:
                # Listar todos los usuarios
                await self.list_all_users(update)
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def list_user_emails(self, update: Update, user_id: int):
        """Lista emails de un usuario específico usando archivos temporales"""
        user_data = db.execute_query(
            "SELECT username, first_name FROM users WHERE id = %s",
            (user_id,)
        )
        
        if not user_data:
            await update.message.reply_text(f"❌ Usuario {user_id} no encontrado")
            return
        
        emails = db.execute_query(
            "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
            (user_id,)
        )
        
        # Usar directorio temporal del sistema
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', prefix=f'emails_{user_id}_', 
                                           encoding='utf-8', delete=False) as temp_file:
                temp_file.write(f"Emails del usuario {user_id}\n")
                temp_file.write("=" * 30 + "\n\n")
                
                if emails:
                    for email_row in emails:
                        temp_file.write(f"{email_row['email']}\n")
                    temp_file.write(f"\nTotal: {len(emails)} emails")
                else:
                    temp_file.write("No hay emails asignados")
                
                temp_filename = temp_file.name
            
            # Enviar archivo temporal
            try:
                with open(temp_filename, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"emails_{user_id}.txt",
                        caption=f"📧 Emails del usuario {user_id}"
                    )
                logger.info(f"✅ Lista de emails del usuario {user_id} enviada correctamente ({len(emails) if emails else 0} emails)")
            finally:
                # Limpiar archivo temporal
                try:
                    os.unlink(temp_filename)
                except OSError:
                    pass
                    
        except Exception as e:
            logger.error(f"❌ Error en list_user_emails: {e}")
            await update.message.reply_text(f"❌ Error creando lista de emails: {str(e)}")
    
    async def list_all_users(self, update: Update):
        """Lista todos los usuarios usando directorio temporal"""
        users = db.execute_query("""
            SELECT id, username, first_name, is_admin, free_access, 
                   expires_at, is_active, created_at
            FROM users ORDER BY id
        """)
        
        if not users:
            await update.message.reply_text("📭 No hay usuarios registrados")
            return
        
        # Usar directorio temporal del sistema
        try:
            # Crear directorio temporal
            temp_dir = tempfile.mkdtemp(prefix='disney_users_')
            files_created = []
            
            for user in users:
                user_id = user['id']
                
                # Obtener emails del usuario
                emails = db.execute_query(
                    "SELECT email FROM user_emails WHERE user_id = %s ORDER BY email",
                    (user_id,)
                )
                
                # Crear archivo para este usuario en el directorio temporal
                user_filename = os.path.join(temp_dir, f"user_{user_id}.txt")
                with open(user_filename, 'w', encoding='utf-8') as f:
                    f.write(f"USUARIO {user_id}\n")
                    f.write("=" * 30 + "\n\n")
                    
                    f.write(f"Username: {user['username'] or 'No establecido'}\n")
                    f.write(f"Nombre: {user['first_name'] or 'No establecido'}\n")
                    f.write(f"Admin: {'Sí' if user['is_admin'] else 'No'}\n")
                    f.write(f"Acceso libre: {'Sí' if user['free_access'] else 'No'}\n")
                    f.write(f"Activo: {'Sí' if user['is_active'] else 'No'}\n")
                    f.write(f"Creado: {user['created_at']}\n")
                    f.write(f"Expira: {user['expires_at'] or 'Sin expiración'}\n\n")
                    
                    f.write("EMAILS ASIGNADOS:\n")
                    f.write("-" * 20 + "\n")
                    
                    if emails:
                        for email_row in emails:
                            f.write(f"• {email_row['email']}\n")
                        f.write(f"\nTotal: {len(emails)} emails")
                    else:
                        f.write("No hay emails asignados\n")
                
                files_created.append(user_filename)
            
            # Crear ZIP en el directorio temporal
            zip_filename = os.path.join(temp_dir, f"usuarios_completo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip")
            with zipfile.ZipFile(zip_filename, 'w') as zipf:
                for file_path in files_created:
                    zipf.write(file_path, os.path.basename(file_path))
            
            # Enviar ZIP
            try:
                with open(zip_filename, 'rb') as f:
                    await update.message.reply_document(
                        document=f,
                        filename=f"usuarios_completo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip",
                        caption=f"📊 Lista completa de {len(users)} usuarios"
                    )
                logger.info(f"✅ Lista completa de usuarios enviada correctamente ({len(users)} usuarios)")
            finally:
                # Limpiar directorio temporal completo
                try:
                    shutil.rmtree(temp_dir)
                except OSError:
                    pass
                    
        except Exception as e:
            logger.error(f"❌ Error en list_all_users: {e}")
            await update.message.reply_text(f"❌ Error creando lista de usuarios: {str(e)}")
    
    async def addimap_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /addimap - SIN MARKDOWN PROBLEMÁTICO"""
        if not await self.check_super_admin_only(update):
            return
        
        # Si no hay argumentos, mostrar dominios existentes
        if len(context.args) == 0:
            try:
                configs = db.execute_query("""
                    SELECT domain, email, server, port, created_at
                    FROM imap_configs 
                    ORDER BY domain
                """)
                
                if not configs:
                    await update.message.reply_text(
                        "📭 NO HAY CONFIGURACIONES IMAP\n\n"
                        "💡 Uso: /addimap <domain> <email> <password> <server>\n"
                        "📧 Ejemplo: /addimap gmail.com admin@gmail.com password123 imap.gmail.com"
                    )
                    return
                
                # Crear mensaje con dominios existentes - SIN MARKDOWN
                message = f"📋 CONFIGURACIONES IMAP ({len(configs)}):\n\n"
                
                for config in configs:
                    created_date = config['created_at'].strftime('%Y-%m-%d') if config['created_at'] else 'N/A'
                    message += (
                        f"📧 {config['domain']}\n"
                        f"📧 Email: {config['email']}\n"
                        f"🌐 Servidor: {config['server']}:{config['port']}\n"
                        f"📅 Creado: {created_date}\n\n"
                    )
                
                message += (
                    "💡 COMANDOS:\n"
                    "• /addimap <domain> <email> <password> <server> - Agregar/actualizar\n"
                    "• /delimap <domain> - Eliminar configuración\n"
                    "• /addimap - Ver esta lista"
                )
                
                await update.message.reply_text(message)  # SIN parse_mode
                return
                
            except Exception as e:
                await update.message.reply_text(f"❌ Error consultando configuraciones: {str(e)}")
                return
        
        # Si hay argumentos, procesar como antes
        if len(context.args) < 4:
            await update.message.reply_text(
                "❌ Uso: /addimap <domain> <email> <password> <server>\n\n"
                "📧 Ejemplo: /addimap gmail.com admin@gmail.com password123 imap.gmail.com\n"
                "💡 O usa /addimap para ver configuraciones existentes"
            )
            return
        
        try:
            domain, email, password, server = context.args[:4]

            # ✅ FIX #3: Guardar con cifrado — nunca texto plano en BD
            success = db.save_imap_config_secure(
                domain=domain,
                email=email,
                password=password,
                server=server,
                created_by=update.effective_user.id
            )

            if success:
                await update.message.reply_text(f"✅ Configuración IMAP para {domain} guardada (contraseña cifrada)")
            else:
                await update.message.reply_text(f"❌ Error guardando configuración IMAP para {domain}")

        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def delimap_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /delimap <domain> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /delimap <domain>")
            return
        
        try:
            domain = context.args[0]
            
            result = db.execute_query(
                "DELETE FROM imap_configs WHERE domain = %s",
                (domain,)
            )
            
            if result > 0:
                await update.message.reply_text(f"✅ Configuración IMAP para {domain} eliminada")
            else:
                await update.message.reply_text(f"❌ No se encontró configuración para {domain}")
                
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def deluser_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /deluser <user_id> con eliminación segura"""
        if not await self.check_admin_permissions(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /deluser <user_id>")
            return
        
        try:
            user_id = int(context.args[0])
            
            # Usar la nueva función de eliminación segura que maneja constraints
            db.safe_delete_user(user_id)
            
            await update.message.reply_text(f"✅ Usuario {user_id} eliminado completamente con todos sus registros relacionados")
                
        except ValueError as e:
            if "debe ser un número" in str(e):
                await update.message.reply_text("❌ El user_id debe ser un número")
            else:
                await update.message.reply_text(f"❌ {str(e)}")
        except Exception as e:
            logger.error(f"Error en deluser_command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def addadmin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """✅ CORREGIDO: Comando /addadmin - SIN MARKDOWN PROBLEMÁTICO"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ Uso: /addadmin <user_id> <email1> [email2...]\n\n"
                "📧 Especifica los emails que el admin podrá usar:\n"
                "• /addadmin 123456789 admin@gmail.com admin@yahoo.com\n"
                "• El admin solo podrá usar esos emails específicos"
            )
            return
        
        try:
            new_admin_id = int(context.args[0])
            emails = context.args[1:]
            
            if is_super_admin(new_admin_id):
                await update.message.reply_text("❌ Este usuario ya es super administrador")
                return
            
            # Validar formato de emails
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            invalid_emails = [email for email in emails if not re.match(email_pattern, email)]
            
            if invalid_emails:
                invalid_str = ", ".join(invalid_emails)
                await update.message.reply_text(f"❌ Emails con formato inválido: {invalid_str}")
                return
            
            # Verificar si el usuario existe
            user_exists = db.execute_query("SELECT id FROM users WHERE id = %s", (new_admin_id,))
            
            if not user_exists:
                # Crear usuario admin con emails específicos
                expires_at = datetime.now() + timedelta(days=365)  # 1 año para admins
                db.execute_query("""
                    INSERT INTO users (id, is_admin, is_active, expires_at)
                    VALUES (%s, %s, %s, %s)
                """, (new_admin_id, True, True, expires_at))
                
                # Agregar emails asignados
                for email in emails:
                    try:
                        db.execute_query("""
                            INSERT INTO user_emails (user_id, email)
                            VALUES (%s, %s)
                            ON CONFLICT (user_id, email) DO NOTHING
                        """, (new_admin_id, email))
                    except Exception as e:
                        logger.error(f"Error agregando email {email}: {e}")
                
                # ✅ MENSAJE SIN MARKDOWN PROBLEMÁTICO
                emails_preview = ", ".join(emails[:3])
                extra_count = f" (+{len(emails)-3} más)" if len(emails) > 3 else ""
                
                await update.message.reply_text(
                    f"✅ Usuario {new_admin_id} creado como administrador\n"
                    f"📧 Emails asignados: {len(emails)}\n"
                    f"📝 Emails: {emails_preview}{extra_count}"
                )
            else:
                # Actualizar usuario existente y reemplazar emails
                db.execute_query("""
                    UPDATE users SET is_admin = TRUE, is_active = TRUE
                    WHERE id = %s
                """, (new_admin_id,))
                
                # Eliminar emails anteriores
                db.execute_query("DELETE FROM user_emails WHERE user_id = %s", (new_admin_id,))
                
                # Agregar nuevos emails
                for email in emails:
                    try:
                        db.execute_query("""
                            INSERT INTO user_emails (user_id, email)
                            VALUES (%s, %s)
                        """, (new_admin_id, email))
                    except Exception as e:
                        logger.error(f"Error agregando email {email}: {e}")
                
                # ✅ MENSAJE SIN MARKDOWN PROBLEMÁTICO
                emails_preview = ", ".join(emails[:3])
                extra_count = f" (+{len(emails)-3} más)" if len(emails) > 3 else ""
                
                await update.message.reply_text(
                    f"✅ Usuario {new_admin_id} promovido a administrador\n"
                    f"📧 Emails actualizados: {len(emails)}\n"
                    f"📝 Emails: {emails_preview}{extra_count}"
                )
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def deladmin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /deladmin <user_id> - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return
        
        if len(context.args) != 1:
            await update.message.reply_text("❌ Uso: /deladmin <user_id>")
            return
        
        try:
            admin_id = int(context.args[0])
            
            if is_super_admin(admin_id):
                await update.message.reply_text("❌ No se pueden quitar permisos a un super administrador")
                return
            
            # Quitar permisos de admin
            result = db.execute_query("""
                UPDATE users SET is_admin = FALSE 
                WHERE id = %s
            """, (admin_id,))
            
            if result > 0:
                await update.message.reply_text(f"✅ Permisos de administrador removidos del usuario {admin_id}")
            else:
                await update.message.reply_text(f"❌ Usuario {admin_id} no encontrado")
                
        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            await update.message.reply_text(f"❌ Error: {str(e)}")
    
    async def exclude_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Comando /ex <user_id> - Excluye a un usuario de la verificación de 6 minutos - SOLO SUPER ADMINS"""
        if not await self.check_super_admin_only(update):
            return

        if len(context.args) != 1:
            await update.message.reply_text(
                "❌ Uso: /ex <user_id>\n\n"
                "💡 Este comando excluye a un usuario de la verificación de 6 minutos.\n"
                "🔓 El usuario podrá hacer búsquedas seguidas sin esperar.\n\n"
                "📋 Ejemplos:\n"
                "• /ex 123456789 - Excluir usuario de verificación\n"
                "• /ex 123456789 - Si ya está excluido, lo volverá a incluir"
            )
            return

        try:
            user_id = int(context.args[0])

            # Verificar si el usuario existe
            user_data = db.execute_query(
                "SELECT id, username, first_name, skip_verification FROM users WHERE id = %s",
                (user_id,)
            )

            if not user_data:
                await update.message.reply_text(
                    f"❌ Usuario {user_id} no encontrado.\n"
                    "💡 El usuario debe estar registrado en el sistema primero."
                )
                return

            user_info = user_data[0]
            current_skip = user_info.get('skip_verification', False)
            username = user_info['username'] or user_info['first_name'] or f"Usuario_{user_id}"

            # Alternar el estado de skip_verification
            new_skip_value = not current_skip

            # Actualizar en la base de datos
            db.execute_query("""
                UPDATE users
                SET skip_verification = %s
                WHERE id = %s
            """, (new_skip_value, user_id))

            if new_skip_value:
                # Usuario excluido de verificación
                await update.message.reply_text(
                    f"✅ Usuario excluido de verificación\n\n"
                    f"👤 Usuario: {username}\n"
                    f"🆔 ID: {user_id}\n\n"
                    f"🔓 PRIVILEGIO ACTIVADO:\n"
                    f"• Puede hacer búsquedas consecutivas sin esperar\n"
                    f"• No tiene que esperar 6 minutos entre búsquedas\n"
                    f"• Puede consultar múltiples emails seguidos\n\n"
                    f"⚠️ NOTA: La verificación de cambio de email sigue activa"
                )
                logger.info(f"✅ Usuario {user_id} ({username}) excluido de verificación de 6 minutos")
            else:
                # Usuario vuelve a tener verificación normal
                await update.message.reply_text(
                    f"✅ Verificación restaurada para usuario\n\n"
                    f"👤 Usuario: {username}\n"
                    f"🆔 ID: {user_id}\n\n"
                    f"🔒 VERIFICACIÓN ACTIVADA:\n"
                    f"• Debe esperar 6 minutos entre búsquedas\n"
                    f"• Sistema de verificación normal aplicado\n\n"
                    f"💡 Usa /ex {user_id} nuevamente para excluir"
                )
                logger.info(f"✅ Usuario {user_id} ({username}) vuelve a tener verificación de 6 minutos")

        except ValueError:
            await update.message.reply_text("❌ El user_id debe ser un número")
        except Exception as e:
            logger.error(f"Error en exclude_command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}")

    async def handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Maneja mensajes de texto (para futuras funcionalidades) - SIN MARKDOWN"""
        # No responder a mensajes normales en grupos
        if not update.effective_chat or update.effective_chat.type != "private":
            return
            
        # Por ahora solo envía un mensaje de ayuda
        if update.message:
            await update.message.reply_text(
                "💡 COMANDOS DISPONIBLES:\n\n"
                "🏰 /check <email> - Buscar códigos Disney\n"
                "📋 /start - Mostrar información de tu cuenta\n\n"
                "📧 EJEMPLO: /check usuario@gmail.com"
            )
    
    async def run_with_shutdown(self, shutdown_event):
        """Ejecuta el bot con manejo de cierre"""
        self.shutdown_event = shutdown_event
        
        try:
            logger.info("🤖 Inicializando bot de Telegram...")
            await self.app.initialize()
            
            logger.info("🤖 Iniciando bot de Telegram...")
            await self.app.start()
            
            # Iniciar polling con timeout personalizado
            await self.app.updater.start_polling(
                timeout=10,
                read_timeout=10,
                write_timeout=10,
                connect_timeout=10,
                pool_timeout=5
            )
            
            logger.info("✅ Bot de Telegram iniciado correctamente")
            
            # Esperar hasta que se señale el cierre
            try:
                await shutdown_event.wait()
                logger.info("🤖 Señal de cierre recibida para el bot")
            except asyncio.CancelledError:
                logger.info("🤖 Bot cancelado")
                raise
            
        except asyncio.CancelledError:
            logger.info("🤖 Bot de Telegram cancelado durante inicialización")
            raise
        except Exception as e:
            logger.error(f"❌ Error crítico en bot: {e}")
            raise
        finally:
            # Limpiar recursos
            try:
                logger.info("🤖 Deteniendo bot de Telegram...")
                
                if self.app.updater.running:
                    await self.app.updater.stop()
                
                await self.app.stop()
                await self.app.shutdown()
                
                logger.info("✅ Bot de Telegram detenido correctamente")
            except Exception as e:
                logger.error(f"❌ Error cerrando bot: {e}")

# Instancia global del bot
bot = DisneyBot()
