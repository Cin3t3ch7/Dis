import os
from dotenv import load_dotenv

load_dotenv()

# Telegram Bot - SECURE: Load from environment variable only
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("BOT_TOKEN must be set in environment variables (.env file)")

# Super Admins - Load from environment variable
SUPER_ADMIN_IDS_STR = os.getenv("SUPER_ADMIN_IDS", "")
if not SUPER_ADMIN_IDS_STR:
    raise ValueError("SUPER_ADMIN_IDS must be set in environment variables (.env file)")
try:
    SUPER_ADMIN_IDS = [int(id.strip()) for id in SUPER_ADMIN_IDS_STR.split(",") if id.strip()]
except ValueError:
    raise ValueError("SUPER_ADMIN_IDS must be a comma-separated list of integers")

# PostgreSQL Database - SECURE: No default credentials
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL must be set in environment variables (.env file)")

# Web Security - SECURE: Generate strong secret key, no predictable defaults
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY must be set in environment variables (.env file). Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Disney Regex Patterns - Patrones mejorados y más específicos
DISNEY_PATTERNS = {
    'disney_code': r'<td[^>]*>\s*(\d{4,8})\s*</td>',  # Códigos de 4-8 dígitos en tabla
    'disney_household': r'(?:Household|household)[\s\S]*?<td[^>]*>\s*(\d{6,8})\s*</td>',  # Household codes
    'disney_mydisney': r'(?:otp_code|verification[_\s]code)[^>]*>\s*(\d{4,8})\s*<',  # OTP codes
    'disney_general': r'(?:código|code|verification)[\s:]*(\d{4,8})',  # Códigos generales
    'disney_plain': r'\b(\d{6})\b'  # Códigos de 6 dígitos simples
}

# Direcciones de email de Disney
DISNEY_FROM_ADDRESSES = [
    'disneyplus@trx.mail2.disneyplus.com'
]

# ═══════════════════════════════════════════════════════════════════════
# Configuración Multi-Servicio (para la web)
# Disney usa DISNEY_PATTERNS/DISNEY_FROM_ADDRESSES existentes (compatibilidad bot)
# Los demás servicios NO tienen verificación de 6 minutos ni detección de cambio de email
# ═══════════════════════════════════════════════════════════════════════
SERVICE_CONFIG = {
    'max': {
        'name': 'Max',
        'from_addresses': ['no-reply@alerts.hbomax.com'],
        'sub_options': {
            'max_reset': {
                'label': 'Link de Restablecimiento',
                'pattern': r'https:\/\/auth\.hbomax\.com\/set-new-password\?passwordResetToken=[a-zA-Z0-9_\-=]+',
            },
            'max_code': {
                'label': 'Código de Activación',
                'pattern': r'-{3,}\s+(\d{6})',
            },
        },
    },
    'netflix': {
        'name': 'Netflix',
        'from_addresses': ['info@account.netflix.com'],
        'sub_options': {
            'netflix_reset': {
                'label': 'Link de Restablecimiento',
                'pattern': r'https:\/\/www\.netflix\.com\/password\?g=[^"\s<>]+',
            },
            'netflix_update_home': {
                'label': 'Actualizar Hogar',
                'pattern': r'https:\/\/www\.netflix\.com\/account\/update-primary-location\?nftoken=[a-zA-Z0-9%+=&\/]+',
            },
            'netflix_home_code': {
                'label': 'Código de Hogar',
                'pattern': r'https:\/\/www\.netflix\.com\/account\/travel\/verify\?nftoken=[a-zA-Z0-9%+=\/]+',
            },
            'netflix_login_code': {
                'label': 'Código de Inicio de Sesión',
                'pattern': r'lrg-number[^>]*>\s*(\d{4})\s*<\/td>',
            },
            'netflix_close_sessions': {
                'label': 'Netflix Cerrar Sesiones',
                'pattern': r'<td\b[^>]*>\s*([0-9]{6})\s*<\/td>',
            },
            'netflix_activation': {
                'label': 'Link de Activación',
                'pattern': r'https:\/\/www\.netflix\.com\/ilum\?code=[a-zA-Z0-9%+=&\/]+',
            },
        },
    },
}


# Configuración del sistema de verificación
VERIFICATION_DELAY_SECONDS = 360  # Tiempo de espera antes de verificar cambios (6 minutos)
MAX_VERIFICATION_THREADS = 50   # Máximo número de threads de verificación simultáneos

# Configuración de reconexión
MAX_DB_RETRIES = 5
DB_RETRY_DELAY = 2
MAX_IMAP_RETRIES = 3
IMAP_RETRY_DELAY = 2

# Configuración de timeouts
IMAP_TIMEOUT = 30
WEB_TIMEOUT = 30
BOT_TIMEOUT = 30

# Configuración de logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# Configuración para producción
PRODUCTION = os.getenv("PRODUCTION", "true").lower() == "true"
HOST = "0.0.0.0" if PRODUCTION else "127.0.0.1"
PORT = int(os.getenv("PORT", "8000"))

# Función helper para verificar si un usuario es super admin
def is_super_admin(user_id):
    """Verifica si un usuario es super admin"""
    return user_id in SUPER_ADMIN_IDS

# Función para obtener el primer super admin (para compatibilidad)
def get_primary_super_admin():
    """Obtiene el primer super admin de la lista"""
    return SUPER_ADMIN_IDS[0] if SUPER_ADMIN_IDS else None

# Configuración de Seguridad para API
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", str(2 * 1024 * 1024))) # Por defecto 2MB

