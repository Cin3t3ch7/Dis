#!/usr/bin/env python3
"""
Script para verificar y corregir la configuración de zona horaria de PostgreSQL
"""
import logging
from database import db
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def check_timezone():
    """Verifica la zona horaria actual de PostgreSQL"""
    try:
        logger.info("=" * 60)
        logger.info("🔍 VERIFICACIÓN DE ZONA HORARIA")
        logger.info("=" * 60)

        # 1. Verificar timezone de PostgreSQL
        pg_timezone = db.execute_query("SHOW timezone")
        if pg_timezone and isinstance(pg_timezone, list) and len(pg_timezone) > 0:
            logger.info(f"📍 PostgreSQL timezone: {pg_timezone[0]['timezone']}")
        else:
            logger.warning("⚠️ No se pudo obtener timezone de PostgreSQL")

        # 2. Verificar hora actual de PostgreSQL en diferentes formatos
        pg_times = db.execute_query("""
            SELECT
                NOW() as now_default,
                NOW() AT TIME ZONE 'UTC' as now_utc,
                CURRENT_TIMESTAMP as current_timestamp,
                timezone('UTC', NOW()) as timezone_utc
        """)

        if pg_times and isinstance(pg_times, list) and len(pg_times) > 0:
            logger.info(f"\n⏰ TIEMPOS DE POSTGRESQL:")
            logger.info(f"   NOW():                {pg_times[0]['now_default']}")
            logger.info(f"   NOW() AT TIME ZONE 'UTC': {pg_times[0]['now_utc']}")
            logger.info(f"   CURRENT_TIMESTAMP:    {pg_times[0]['current_timestamp']}")
            logger.info(f"   timezone('UTC', NOW()): {pg_times[0]['timezone_utc']}")
        else:
            logger.warning("⚠️ No se pudo obtener tiempos de PostgreSQL")

        # 3. Verificar hora de Python
        python_utc = datetime.now(timezone.utc)
        logger.info(f"\n🐍 TIEMPO DE PYTHON:")
        logger.info(f"   datetime.now(timezone.utc): {python_utc.isoformat()}")

        # 4. Verificar si hay búsquedas activas con timestamps problemáticos
        active_searches = db.execute_query("""
            SELECT user_id, email, started_at,
                   (started_at AT TIME ZONE 'UTC') as started_at_utc
            FROM active_search_requests
            LIMIT 5
        """)

        if active_searches and isinstance(active_searches, list) and len(active_searches) > 0:
            logger.info(f"\n🔍 BÚSQUEDAS ACTIVAS (últimas 5):")
            for search in active_searches:
                logger.info(f"   User {search['user_id']}: started={search['started_at']}, utc={search['started_at_utc']}")
        else:
            logger.info(f"\n✅ No hay búsquedas activas")

        logger.info("\n" + "=" * 60)

    except Exception as e:
        logger.error(f"❌ Error verificando timezone: {e}")

def fix_timezone():
    """Intenta corregir la zona horaria de PostgreSQL a UTC"""
    try:
        logger.info("\n🔧 INTENTANDO CORREGIR ZONA HORARIA...")

        # Intentar cambiar timezone a UTC
        try:
            db.execute_query("SET timezone = 'UTC'")
            logger.info("✅ Timezone de sesión cambiado a UTC (temporal)")
        except Exception as e:
            logger.warning(f"⚠️ No se pudo cambiar timezone de sesión: {e}")

        # Verificar si funcionó
        pg_timezone = db.execute_query("SHOW timezone")
        if pg_timezone and isinstance(pg_timezone, list) and len(pg_timezone) > 0:
            logger.info(f"📍 Nueva timezone: {pg_timezone[0]['timezone']}")
        else:
            logger.warning("⚠️ No se pudo verificar la nueva timezone")

        logger.info("\n" + "=" * 60)
        logger.info("⚠️  NOTA: Este cambio es TEMPORAL (solo para esta sesión)")
        logger.info("Para cambio PERMANENTE, ejecuta estos comandos en el servidor:")
        logger.info("")
        logger.info("   # Opción 1: Cambiar configuración de PostgreSQL")
        logger.info("   sudo -u postgres psql -c \"ALTER SYSTEM SET timezone = 'UTC';\"")
        logger.info("   sudo -u postgres psql -c \"SELECT pg_reload_conf();\"")
        logger.info("")
        logger.info("   # Opción 2: Editar postgresql.conf")
        logger.info("   sudo nano /etc/postgresql/*/main/postgresql.conf")
        logger.info("   # Buscar 'timezone' y cambiar a: timezone = 'UTC'")
        logger.info("   sudo systemctl restart postgresql")
        logger.info("")
        logger.info("   # También cambiar zona horaria del sistema:")
        logger.info("   sudo timedatectl set-timezone UTC")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"❌ Error corrigiendo timezone: {e}")

def clean_active_searches():
    """Limpia todas las búsquedas activas (útil después de corregir timezone)"""
    try:
        logger.info("\n🧹 LIMPIANDO BÚSQUEDAS ACTIVAS...")

        result = db.cleanup_all_active_searches()
        if result is None:
            result = 0
        logger.info(f"✅ {result} búsquedas activas limpiadas")

    except Exception as e:
        logger.error(f"❌ Error limpiando búsquedas: {e}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "fix":
        check_timezone()
        fix_timezone()
        clean_active_searches()
    elif len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean_active_searches()
    else:
        check_timezone()
        logger.info("\n💡 Uso:")
        logger.info("   python fix_timezone.py       - Solo verificar")
        logger.info("   python fix_timezone.py fix   - Verificar y corregir (temporal)")
        logger.info("   python fix_timezone.py clean - Limpiar búsquedas activas")

