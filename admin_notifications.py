"""
📢 ADMIN NOTIFICATIONS MODULE - Disney Search Pro
================================================
Módulo centralizado para enviar notificaciones de actividad
a los super administradores vía Telegram.

Registra toda la actividad de búsquedas (código encontrado/no encontrado)
de todos los usuarios desde cualquier plataforma (Bot / Web).
"""

import logging
import asyncio
import threading
from datetime import datetime, timezone
from typing import Optional
from config import SUPER_ADMIN_IDS, BOT_TOKEN

logger = logging.getLogger(__name__)


def _send_telegram_message(message: str):
    """Envía un mensaje a todos los super admins vía Telegram Bot API (httpx directo).
    Funciona desde cualquier contexto (async o sync, con o sin event loop).
    """
    def _do_send():
        try:
            import httpx
            with httpx.Client(timeout=10.0) as client:
                for admin_id in SUPER_ADMIN_IDS:
                    try:
                        resp = client.post(
                            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                            json={
                                "chat_id": admin_id,
                                "text": message
                            }
                        )
                        if resp.status_code == 200:
                            logger.info(f"✅ Notificación enviada al admin {admin_id}")
                        else:
                            logger.warning(f"⚠️ Telegram API respondió {resp.status_code} para admin {admin_id}: {resp.text[:100]}")
                    except Exception as e:
                        logger.warning(f"⚠️ No se pudo notificar al admin {admin_id}: {e}")
        except ImportError:
            logger.error("❌ httpx no está instalado — no se pueden enviar notificaciones")
        except Exception as e:
            logger.warning(f"⚠️ Error enviando notificación admin: {e}")

    # Ejecutar en thread daemon para no bloquear el flujo principal
    t = threading.Thread(target=_do_send, daemon=True)
    t.start()


def notify_search_activity(
    user_id: int,
    username: str,
    email: str,
    source: str,
    service: str,
    found: bool,
    code: Optional[str] = None,
    code_type: Optional[str] = None,
    sub_option: Optional[str] = None
):
    """
    Notifica a los super admins sobre actividad de búsqueda.

    Args:
        user_id: ID del usuario que buscó
        username: Nombre/username del usuario
        email: Email buscado (se muestra completo)
        source: Origen ('telegram' o 'web')
        service: Servicio ('disney', 'crunchyroll', 'max', 'prime')
        found: Si se encontró resultado
        code: Código encontrado (si aplica)
        code_type: Tipo de código (si aplica)
        sub_option: Sub-opción usada (si aplica)
    """
    try:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        # Limpiar source string (quitar "SearchSource.")
        source_clean = str(source).replace("SearchSource.", "").lower()
        source_emoji = "🤖" if source_clean == "telegram" else "🌐"
        source_text = "Telegram Bot" if source_clean == "telegram" else "Página Web"
        result_emoji = "✅" if found else "❌"

        # Construir mensaje
        lines = [
            f"📊 ACTIVIDAD DE BÚSQUEDA",
            f"",
            f"👤 Usuario: {username} (ID: {user_id})",
            f"📧 Email: {email}",
            f"{source_emoji} Plataforma: {source_text}",
            f"🔍 Servicio: {service.upper()}",
        ]

        if sub_option:
            lines.append(f"📋 Opción: {sub_option}")

        lines.append(f"")

        if found:
            lines.append(f"{result_emoji} CÓDIGO ENCONTRADO")
            if code_type:
                lines.append(f"📝 Tipo: {code_type}")
            if code:
                lines.append(f"🔑 Código: {code}")
        else:
            lines.append(f"{result_emoji} No se encontraron resultados")

        lines.append(f"")
        lines.append(f"🕐 Fecha: {now}")

        message = "\n".join(lines)

        # Log local
        logger.info(
            f"📊 Búsqueda: user={user_id}, email={email}, "
            f"source={source_clean}, service={service}, found={found}"
        )

        # Enviar a admins vía Telegram (en thread separado, no bloquea)
        _send_telegram_message(message)

    except Exception as e:
        logger.error(f"❌ Error en notify_search_activity: {e}")


def notify_search_error(
    user_id: int,
    username: str,
    email: str,
    source: str,
    error_msg: str
):
    """
    Notifica a los super admins sobre errores en búsquedas.

    Args:
        user_id: ID del usuario
        username: Nombre/username del usuario
        email: Email buscado (se muestra completo)
        source: Origen ('telegram' o 'web')
        error_msg: Mensaje de error
    """
    try:
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        source_clean = str(source).replace("SearchSource.", "").lower()
        source_emoji = "🤖" if source_clean == "telegram" else "🌐"
        source_text = "Telegram Bot" if source_clean == "telegram" else "Página Web"

        # Truncar error para evitar mensajes muy largos
        short_error = error_msg[:200] if len(error_msg) > 200 else error_msg

        # No notificar errores de validación normales
        skip_patterns = ["BÚSQUEDA EN VERIFICACIÓN", "Usuario bloqueado", "Sin permisos"]
        if any(pattern in error_msg for pattern in skip_patterns):
            return

        message = (
            f"⚠️ ERROR EN BÚSQUEDA\n\n"
            f"👤 Usuario: {username} (ID: {user_id})\n"
            f"📧 Email: {email}\n"
            f"{source_emoji} Plataforma: {source_text}\n"
            f"🚫 Error: {short_error}\n"
            f"🕐 Fecha: {now}"
        )

        _send_telegram_message(message)

    except Exception as e:
        logger.error(f"❌ Error en notify_search_error: {e}")
