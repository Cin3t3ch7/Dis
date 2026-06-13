"""
🏷️ ENUMS MODULE - Disney Search Pro
================================================
Enumeraciones centralizadas para evitar magic strings.
Heredan de str para compatibilidad directa con PostgreSQL y JSON.
"""

from enum import Enum


class SearchSource(str, Enum):
    """Origen de la solicitud de búsqueda"""
    TELEGRAM = "telegram"
    WEB = "web"


class SearchStatus(str, Enum):
    """Estado de una búsqueda activa"""
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class AccessType(str, Enum):
    """Tipo de acceso del usuario"""
    SUPER_ADMIN = "super_admin"
    ADMIN_RESTRICTED = "admin_restricted"
    FREE_ACCESS = "free_access"
    USER_RESTRICTED = "user_restricted"
