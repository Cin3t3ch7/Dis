"""
🔐 PERMISSIONS MODULE - Disney Search Pro
================================================
Módulo centralizado para verificación de permisos de email.
Elimina la duplicación entre telegram_bot.py y web_app.py (DRY).
"""

import logging
from database import db
from config import is_super_admin

logger = logging.getLogger(__name__)


def can_use_email(user_id: int, email: str, is_admin: bool = False,
                  is_super: bool = False, free_access: bool = False) -> bool:
    """
    Verificación centralizada de permisos de email (case-insensitive).

    Args:
        user_id: ID del usuario
        email: Email a verificar
        is_admin: Si el usuario es admin
        is_super: Si el usuario es super admin
        free_access: Si el usuario tiene acceso libre

    Returns:
        True si el usuario puede usar el email
    """
    # Super admins tienen acceso a todos los emails
    if is_super:
        logger.debug(f"✅ Super admin {user_id} — acceso total")
        return True

    # Usuarios con acceso libre
    if free_access:
        logger.debug(f"✅ Usuario {user_id} con free_access — acceso total")
        return True

    # Admin normal o usuario normal: verificar emails asignados
    try:
        assigned = db.execute_query(
            "SELECT id FROM user_emails WHERE user_id = %s AND LOWER(email) = LOWER(%s)",
            (user_id, email)
        )

        if assigned:
            logger.debug(f"✅ Usuario {user_id} tiene email {_mask_email(email)} asignado")
            return True
        else:
            logger.debug(f"❌ Usuario {user_id} NO tiene email {_mask_email(email)} asignado")
            return False
    except Exception as e:
        logger.error(f"❌ Error verificando permisos de email para usuario {user_id}: {e}")
        return False


def _mask_email(email: str) -> str:
    """Enmascara un email para logging seguro: user@domain → u***@domain"""
    try:
        local, domain = email.split('@', 1)
        if len(local) <= 1:
            return f"{local}***@{domain}"
        return f"{local[0]}***@{domain}"
    except Exception:
        return "***"
