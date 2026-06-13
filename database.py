import os
import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool  # ✅ AUDIT: Thread-safe nativo
from contextlib import contextmanager
import logging
import time
from datetime import datetime, timedelta
from config import DATABASE_URL, SUPER_ADMIN_IDS, is_super_admin
from encryption import encrypt_password, decrypt_password
from enums import SearchSource, SearchStatus

logger = logging.getLogger(__name__)

# ✅ AUDIT: Pool configurable desde variable de entorno
MAX_POOL_SIZE = int(os.getenv("DB_MAX_POOL_SIZE", "50"))
MIN_POOL_SIZE = int(os.getenv("DB_MIN_POOL_SIZE", "2"))


class Database:
    def __init__(self):
        self.pool = None
        self.init_pool()
        
    def init_pool(self):
        max_retries = 5
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                self.pool = ThreadedConnectionPool(
                    minconn=MIN_POOL_SIZE,
                    maxconn=MAX_POOL_SIZE,
                    dsn=DATABASE_URL,
                    cursor_factory=psycopg2.extras.RealDictCursor
                )
                logger.info(f"✅ ThreadedConnectionPool inicializado (min={MIN_POOL_SIZE}, max={MAX_POOL_SIZE})")
                self.create_tables()
                return
            except Exception as e:
                logger.error(f"❌ Error inicializando pool (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                else:
                    raise

    def get_connection(self):
        """Obtiene conexión del pool thread-safe (sin lock manual)"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if self.pool is None or self.pool.closed:
                    self.init_pool()
                return self.pool.getconn()  # ✅ ThreadedConnectionPool es thread-safe
            except Exception as e:
                logger.error(f"❌ Error obteniendo conexión (intento {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)
                    try:
                        self.init_pool()
                    except:
                        pass
                else:
                    raise
    
    def put_connection(self, conn):
        """Devuelve conexión al pool"""
        try:
            if self.pool and conn and not self.pool.closed:
                self.pool.putconn(conn)
        except psycopg2.pool.PoolError as e:
            # ✅ AUDIT: Ignorar "unkeyed connection" tras reconexiones del pool
            logger.debug(f"⚠️ Pool putconn ignorado: {e}")
        except Exception as e:
            logger.error(f"❌ Error devolviendo conexión: {e}")

    @contextmanager
    def _get_db_connection(self):
        """Context manager para conexiones con cleanup garantizado"""
        conn = self.get_connection()
        try:
            yield conn
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            self.put_connection(conn)
    
    def execute_query(self, query, params=None):
        conn = None
        cursor = None
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                # ✅ AUDIT: Soportar tanto str como psycopg2.sql.Composed
                if isinstance(query, str):
                    query_str = query.strip().upper()
                else:
                    # psycopg2.sql.Composed/SQL — convertir a string para inspección
                    query_str = query.as_string(conn).strip().upper()
                
                if query_str.startswith('SELECT'):
                    result = cursor.fetchall()
                else:
                    conn.commit()
                    result = cursor.rowcount
                
                return result
                
            except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
                logger.error(f"❌ Error de conexión DB (intento {attempt + 1}/{max_retries}): {e}")
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                if attempt < max_retries - 1:
                    time.sleep(1)
                    try:
                        self.init_pool()
                    except:
                        pass
                else:
                    raise
            except Exception as e:
                if conn:
                    try:
                        conn.rollback()
                    except:
                        pass
                logger.error(f"❌ Error ejecutando query: {e}")
                raise
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except:
                        pass
                if conn:
                    self.put_connection(conn)

    def create_tables(self):
        """CORREGIDO: Crea tablas y aplica todas las correcciones automáticamente con CASCADE FK"""
        logger.info("🔧 Inicializando base de datos con auto-reparación y foreign keys corregidas...")
        
        tables = [
            # Tabla de usuarios (principal)
            """
            CREATE TABLE IF NOT EXISTS users (
                id BIGINT PRIMARY KEY,
                username VARCHAR(255),
                first_name VARCHAR(255),
                last_name VARCHAR(255),
                is_admin BOOLEAN DEFAULT FALSE,
                free_access BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                is_blocked BOOLEAN DEFAULT FALSE,
                blocked_reason TEXT,
                blocked_at TIMESTAMP
            )
            """,
            # Tabla de emails de usuarios (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS user_emails (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, email)
            )
            """,
            # Tabla de configuraciones IMAP
            """
            CREATE TABLE IF NOT EXISTS imap_configs (
                id SERIAL PRIMARY KEY,
                domain VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) NOT NULL,
                password VARCHAR(255) NOT NULL,
                server VARCHAR(255) NOT NULL,
                port INTEGER DEFAULT 993,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by BIGINT REFERENCES users(id) ON DELETE SET NULL
            )
            """,
            # Tabla de sesiones web (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS web_sessions (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                session_token VARCHAR(255) UNIQUE NOT NULL,
                csrf_token VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
            """,
            # CORREGIDO: Tabla de búsquedas Disney (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS disney_searches (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                result_type VARCHAR(50),
                result_code VARCHAR(255),
                search_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verification_scheduled BOOLEAN DEFAULT FALSE,
                verification_completed BOOLEAN DEFAULT FALSE
            )
            """,
            # CORREGIDO: Tabla de verificaciones de cambio de email (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS email_change_verifications (
                id SERIAL PRIMARY KEY,
                search_id INTEGER REFERENCES disney_searches(id) ON DELETE CASCADE,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                email VARCHAR(255) NOT NULL,
                original_code VARCHAR(255),
                scheduled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                verified_at TIMESTAMP,
                email_changed BOOLEAN DEFAULT FALSE,
                user_blocked BOOLEAN DEFAULT FALSE
            )
            """,
            # NUEVO: Tabla de solicitudes activas para control de límites
            # CORREGIDO: Usar TIMESTAMPTZ para timestamps con zona horaria
            """
            create table if not exists active_search_requests (
                id serial primary key,
                user_id bigint references users(id) on delete cascade,
                email varchar(255) not null,
                started_at timestamptz default (now() at time zone 'utc'),
                source varchar(50) default 'telegram',
                status varchar(50) default 'processing',
                unique(user_id)
            )
            """,
            # Tabla de códigos de verificación OTP (CASCADE FK)
            """
            CREATE TABLE IF NOT EXISTS verification_codes (
                id SERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                code VARCHAR(6) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            # ✅ NUEVO: Tabla de rate limiting para OTP (CRÍTICO - Previene fuerza bruta)
            """
            CREATE TABLE IF NOT EXISTS rate_limit_otp (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT FALSE
            )
            """,
            # ✅ NUEVO: Tabla de rate limiting para Login
            """
            CREATE TABLE IF NOT EXISTS rate_limit_login (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT FALSE
            )
            """,
            # ✅ NUEVO: Tabla de rate limiting para Búsquedas
            """
            CREATE TABLE IF NOT EXISTS rate_limit_search (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                email VARCHAR(255),
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT FALSE
            )
            """
        ]
        
        # Crear tablas básicas
        for i, table_sql in enumerate(tables, 1):
            try:
                self.execute_query(table_sql)
                logger.info(f"Tabla {i}/{len(tables)} creada/verificada")
            except Exception as e:
                logger.error(f"❌ Error creando tabla {i}: {e}")
        
        # NUEVO: Aplicar correcciones de foreign keys para tablas existentes
        self.fix_foreign_key_constraints()

        # ✅ NUEVO: Crear índices para rate limiting (mejora rendimiento)
        self.create_rate_limit_indexes()

        # ✅ AUDIT: Crear índices de rendimiento para alta concurrencia
        self.create_performance_indexes()

        # Aplicar correcciones automáticamente
        self.apply_automatic_fixes()
        
        # Crear super admins
        self.create_super_admins()
        
        # Aplicar restricciones para administradores
        self.apply_admin_restrictions()
        
        logger.info("Base de datos inicializada completamente con todas las correcciones aplicadas")
    
    def migrate_started_at_to_timestamptz(self):
        """NUEVO: Migra la columna started_at de TIMESTAMP a TIMESTAMPTZ si es necesario"""
        try:
            logger.info("🔧 Verificando tipo de columna started_at...")

            # Verificar si la tabla existe
            table_exists = self.execute_query("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_name = 'active_search_requests'
                )
            """)

            if not table_exists or not table_exists[0]['exists']:
                logger.info("ℹ️ Tabla active_search_requests no existe aún, se creará con TIMESTAMPTZ")
                return

            # Verificar el tipo de columna actual
            column_type = self.execute_query("""
                SELECT data_type, column_default
                FROM information_schema.columns
                WHERE table_name = 'active_search_requests' AND column_name = 'started_at'
            """)

            if column_type and column_type[0]['data_type'] == 'timestamp without time zone':
                logger.info("🔧 Migrando started_at de TIMESTAMP a TIMESTAMPTZ...")

                # Primero, limpiar todos los registros antiguos para evitar problemas
                cleaned = self.execute_query("DELETE FROM active_search_requests")
                if cleaned:
                    logger.info(f"🧹 {cleaned} búsquedas activas limpiadas antes de migración")

                # Cambiar el tipo de columna a TIMESTAMPTZ
                self.execute_query("""
                    ALTER TABLE active_search_requests
                    ALTER COLUMN started_at TYPE TIMESTAMPTZ
                    USING started_at AT TIME ZONE 'UTC'
                """)

                # Cambiar el default a NOW() AT TIME ZONE 'UTC'
                self.execute_query("""
                    ALTER TABLE active_search_requests
                    ALTER COLUMN started_at SET DEFAULT (NOW() AT TIME ZONE 'UTC')
                """)

                logger.info("✅ Columna started_at migrada a TIMESTAMPTZ con UTC")
            elif column_type and column_type[0]['data_type'] == 'timestamp with time zone':
                logger.info("✅ Columna started_at ya es TIMESTAMPTZ")
            else:
                logger.warning("⚠️ No se pudo determinar el tipo de columna started_at")

        except Exception as e:
            logger.error(f"❌ Error migrando started_at a TIMESTAMPTZ: {e}")

    def create_rate_limit_indexes(self):
        """✅ NUEVO: Crea índices para tablas de rate limiting (mejora rendimiento)"""
        logger.info("🔧 Creando índices para rate limiting...")

        indexes = [
            # Índices para rate_limit_otp
            "CREATE INDEX IF NOT EXISTS idx_otp_user_time ON rate_limit_otp(user_id, attempt_time)",
            "CREATE INDEX IF NOT EXISTS idx_otp_ip_time ON rate_limit_otp(ip_address, attempt_time)",

            # Índices para rate_limit_login
            "CREATE INDEX IF NOT EXISTS idx_login_user_time ON rate_limit_login(user_id, attempt_time)",
            "CREATE INDEX IF NOT EXISTS idx_login_ip_time ON rate_limit_login(ip_address, attempt_time)",

            # Índices para rate_limit_search
            "CREATE INDEX IF NOT EXISTS idx_search_user_time ON rate_limit_search(user_id, attempt_time)",
            "CREATE INDEX IF NOT EXISTS idx_search_ip_time ON rate_limit_search(ip_address, attempt_time)"
        ]

        for index_sql in indexes:
            try:
                self.execute_query(index_sql)
                logger.info(f"✅ Índice creado/verificado")
            except Exception as e:
                logger.warning(f"⚠️ Error creando índice: {e}")

        logger.info("✅ Índices de rate limiting creados")

    def fix_foreign_key_constraints(self):
        """NUEVO: Corrige foreign key constraints existentes para agregar CASCADE"""
        logger.info("🔧 Verificando y corrigiendo foreign key constraints...")

        try:
            # Verificar foreign keys existentes que necesitan CASCADE
            constraint_fixes = [
                {
                    'table': 'disney_searches',
                    'constraint_name': 'disney_searches_user_id_fkey',
                    'column': 'user_id',
                    'references': 'users(id)',
                    'action': 'CASCADE'
                },
                {
                    'table': 'email_change_verifications', 
                    'constraint_name': 'email_change_verifications_user_id_fkey',
                    'column': 'user_id',
                    'references': 'users(id)',
                    'action': 'CASCADE'
                },
                {
                    'table': 'email_change_verifications',
                    'constraint_name': 'email_change_verifications_search_id_fkey', 
                    'column': 'search_id',
                    'references': 'disney_searches(id)',
                    'action': 'CASCADE'
                }
            ]
            
            for fix in constraint_fixes:
                try:
                    # Verificar si la constraint existe
                    constraint_check = self.execute_query("""
                        SELECT constraint_name, delete_rule 
                        FROM information_schema.referential_constraints 
                        WHERE constraint_name = %s
                    """, (fix['constraint_name'],))
                    
                    if constraint_check:
                        current_rule = constraint_check[0].get('delete_rule', 'NO ACTION')
                        
                        if current_rule != 'CASCADE':
                            logger.info(f"🔧 Corrigiendo constraint {fix['constraint_name']} (actual: {current_rule} -> CASCADE)")
                            
                            # Eliminar constraint existente
                            self.execute_query(f"""
                                ALTER TABLE {fix['table']} 
                                DROP CONSTRAINT IF EXISTS {fix['constraint_name']}
                            """)
                            
                            # Agregar constraint corregida
                            self.execute_query(f"""
                                ALTER TABLE {fix['table']} 
                                ADD CONSTRAINT {fix['constraint_name']} 
                                FOREIGN KEY ({fix['column']}) 
                                REFERENCES {fix['references']} 
                                ON DELETE {fix['action']}
                            """)
                            
                            logger.info(f"✅ Constraint {fix['constraint_name']} corregida")
                        else:
                            logger.info(f"✅ Constraint {fix['constraint_name']} ya tiene CASCADE")
                    else:
                        logger.info(f"ℹ️ Constraint {fix['constraint_name']} no existe (se creará con la tabla)")
                        
                except Exception as e:
                    logger.warning(f"⚠️ Error corrigiendo constraint {fix['constraint_name']}: {e}")
                    continue
            
            logger.info("✅ Verificación de foreign key constraints completada")
            
        except Exception as e:
            logger.error(f"❌ Error en corrección de foreign keys: {e}")
    
    def apply_automatic_fixes(self):
        """Aplica todas las correcciones necesarias automáticamente"""
        logger.info("🔧 Aplicando correcciones automáticas...")

        # ✅ NUEVO: Migrar columna started_at a TIMESTAMPTZ si existe
        self.migrate_started_at_to_timestamptz()

        # ✅ NUEVO: Limpiar búsquedas activas obsoletas al iniciar
        self.cleanup_stale_requests(timeout_minutes=10)

        # Lista de correcciones a aplicar
        fixes = [
            # Agregar columnas faltantes a users si no existen
            {
                'name': 'is_blocked en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='is_blocked') THEN
                        ALTER TABLE users ADD COLUMN is_blocked BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'blocked_reason en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_reason') THEN
                        ALTER TABLE users ADD COLUMN blocked_reason TEXT;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'blocked_at en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='blocked_at') THEN
                        ALTER TABLE users ADD COLUMN blocked_at TIMESTAMP;
                    END IF;
                END $$;
                """
            },
            
            # Agregar columnas faltantes a disney_searches si no existen
            {
                'name': 'verification_scheduled en disney_searches',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_scheduled') THEN
                        ALTER TABLE disney_searches ADD COLUMN verification_scheduled BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            {
                'name': 'verification_completed en disney_searches',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='disney_searches' AND column_name='verification_completed') THEN
                        ALTER TABLE disney_searches ADD COLUMN verification_completed BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },
            
            # Agregar columna skip_verification a users si no existe
            {
                'name': 'skip_verification en users',
                'query': """
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='skip_verification') THEN
                        ALTER TABLE users ADD COLUMN skip_verification BOOLEAN DEFAULT FALSE;
                    END IF;
                END $$;
                """
            },

            # Actualizar valores NULL
            {
                'name': 'Actualizar is_blocked NULL',
                'query': "UPDATE users SET is_blocked = FALSE WHERE is_blocked IS NULL;"
            },
            {
                'name': 'Actualizar verification_scheduled NULL',
                'query': "UPDATE disney_searches SET verification_scheduled = FALSE WHERE verification_scheduled IS NULL;"
            },
            {
                'name': 'Actualizar verification_completed NULL',
                'query': "UPDATE disney_searches SET verification_completed = FALSE WHERE verification_completed IS NULL;"
            },
            {
                'name': 'Actualizar skip_verification NULL',
                'query': "UPDATE users SET skip_verification = FALSE WHERE skip_verification IS NULL;"
            }
        ]
        
        # Aplicar cada corrección
        for fix in fixes:
            try:
                self.execute_query(fix['query'])
                logger.info(f"✅ Corrección aplicada: {fix['name']}")
            except Exception as e:
                logger.warning(f"⚠️ Corrección {fix['name']}: {e}")
                continue
    
    def create_super_admins(self):
        """Crea todos los super admins definidos en SUPER_ADMIN_IDS"""
        logger.info("👑 Configurando super administradores...")
        
        try:
            for i, admin_id in enumerate(SUPER_ADMIN_IDS):
                # Verificar si existe
                existing = self.execute_query(
                    "SELECT id FROM users WHERE id = %s", 
                    (admin_id,)
                )
                
                if not existing:
                    # Crear super admin
                    username = f'SuperAdmin_{i+1}' if i > 0 else 'SuperAdmin'
                    first_name = f'Super Administrator {i+1}' if i > 0 else 'Super Administrator'
                    
                    self.execute_query("""
                        INSERT INTO users (id, username, first_name, is_admin, free_access, is_active)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (admin_id, username, first_name, True, True, True))
                    logger.info(f"✅ Super admin {i+1} creado: {admin_id}")
                else:
                    # Asegurar que tenga los permisos correctos
                    self.execute_query("""
                        UPDATE users SET is_admin = TRUE, free_access = TRUE, is_active = TRUE, is_blocked = FALSE
                        WHERE id = %s
                    """, (admin_id,))
                    logger.info(f"✅ Super admin {i+1} verificado/actualizado: {admin_id}")
        except Exception as e:
            logger.error(f"❌ Error creando super admins: {e}")
    
    def apply_admin_restrictions(self):
        """Aplica automáticamente las restricciones para administradores normales"""
        logger.info("🛡️ Aplicando restricciones para administradores normales...")
        
        try:
            # Remover acceso libre de administradores normales (que no sean super admins)
            result = self.execute_query("""
                UPDATE users 
                SET free_access = FALSE 
                WHERE is_admin = TRUE AND id != ALL(%s)
            """, (SUPER_ADMIN_IDS,))
            
            if result > 0:
                logger.info(f"✅ Acceso libre removido de {result} administradores normales")
            
            # Verificar administradores existentes
            admins = self.execute_query("""
                SELECT u.id, u.username, u.first_name, 
                       COUNT(ue.email) as email_count
                FROM users u
                LEFT JOIN user_emails ue ON u.id = ue.user_id
                WHERE u.is_admin = TRUE AND u.id != ALL(%s)
                GROUP BY u.id, u.username, u.first_name
            """, (SUPER_ADMIN_IDS,))
            
            if admins:
                logger.info(f"📋 Administradores normales encontrados: {len(admins)}")

                admins_with_emails = 0
                admins_without_emails = 0

                for admin in admins:
                    admin_id = admin['id']
                    username = admin['username']
                    first_name = admin['first_name']
                    email_count = admin['email_count']
                    name = username or first_name or f"Admin_{admin_id}"

                    if email_count > 0:
                        admins_with_emails += 1
                        logger.info(f"   ✅ {name} (ID: {admin_id}) - {email_count} emails asignados")
                    else:
                        admins_without_emails += 1
                        logger.warning(f"   ⚠️  {name} (ID: {admin_id}) - SIN EMAILS (usar /addadmin para asignar)")

                logger.info(f"📊 Resumen: {admins_with_emails} con emails, {admins_without_emails} sin emails")

                if admins_without_emails > 0:
                    logger.warning(f"⚠️  {admins_without_emails} administradores necesitan emails asignados")
                    logger.info("💡 Usa /addadmin <user_id> <email1> [email2...] para asignar emails")
            else:
                logger.info("ℹ️ No se encontraron administradores normales")
        
        except Exception as e:
            logger.error(f"❌ Error aplicando restricciones de administradores: {e}")
    
    def check_database_health(self):
        """✅ MEJORADO: Verifica el estado de salud de la base de datos incluyendo foreign keys"""
        try:
            logger.info("🔍 Verificando estado de salud de la base de datos...")
            
            # Verificar tablas principales
            required_tables = [
                'users', 'user_emails', 'imap_configs', 
                'web_sessions', 'disney_searches', 'email_change_verifications'
            ]
            
            for table in required_tables:
                result = self.execute_query("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_name = %s
                """, (table,))
                
                if not result:
                    logger.error(f"❌ Tabla faltante: {table}")
                    return False
            
            # Verificar columnas críticas
            critical_columns = [
                ('users', ['is_blocked', 'blocked_reason', 'blocked_at']),
                ('disney_searches', ['verification_scheduled', 'verification_completed'])
            ]
            
            for table, columns in critical_columns:
                for column in columns:
                    result = self.execute_query("""
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name = %s AND column_name = %s
                    """, (table, column))
                    
                    if not result:
                        logger.error(f"❌ Columna faltante: {table}.{column}")
                        return False
            
            # ✅ NUEVO: Verificar foreign key constraints críticas
            critical_constraints = [
                ('disney_searches_user_id_fkey', 'CASCADE'),
                ('email_change_verifications_user_id_fkey', 'CASCADE'),
                ('user_emails_user_id_fkey', 'CASCADE'),
                ('web_sessions_user_id_fkey', 'CASCADE')
            ]
            
            for constraint_name, expected_rule in critical_constraints:
                constraint_info = self.execute_query("""
                    SELECT constraint_name, delete_rule 
                    FROM information_schema.referential_constraints 
                    WHERE constraint_name = %s
                """, (constraint_name,))
                
                if not constraint_info:
                    logger.warning(f"⚠️ Constraint faltante: {constraint_name}")
                elif constraint_info[0]['delete_rule'] != expected_rule:
                    logger.warning(f"⚠️ Constraint {constraint_name} tiene regla {constraint_info[0]['delete_rule']}, esperada: {expected_rule}")
                else:
                    logger.info(f"✅ Constraint {constraint_name} correcta")
            
            # Verificar super admins
            super_admin_count = self.execute_query("""
                SELECT COUNT(*) as count 
                FROM users 
                WHERE id = ANY(%s) AND is_admin = TRUE AND is_active = TRUE
            """, (SUPER_ADMIN_IDS,))
            
            if not super_admin_count or super_admin_count[0]['count'] != len(SUPER_ADMIN_IDS):
                logger.warning("⚠️ No todos los super administradores están configurados correctamente")
                return False
            
            # Verificar integridad referencial
            integrity_checks = [
                {
                    'name': 'disney_searches -> users',
                    'query': """
                        SELECT COUNT(*) as count FROM disney_searches ds 
                        LEFT JOIN users u ON ds.user_id = u.id 
                        WHERE u.id IS NULL
                    """
                },
                {
                    'name': 'user_emails -> users', 
                    'query': """
                        SELECT COUNT(*) as count FROM user_emails ue 
                        LEFT JOIN users u ON ue.user_id = u.id 
                        WHERE u.id IS NULL
                    """
                }
            ]
            
            for check in integrity_checks:
                result = self.execute_query(check['query'])
                orphaned_count = result[0]['count'] if result else 0
                
                if orphaned_count > 0:
                    logger.warning(f"⚠️ {orphaned_count} registros huérfanos en {check['name']}")
                else:
                    logger.info(f"✅ Integridad referencial correcta: {check['name']}")
            
            logger.info("✅ Base de datos en estado saludable")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error verificando estado de la base de datos: {e}")
            return False

    def safe_delete_user(self, user_id):
        """✅ NUEVO: Elimina un usuario de forma segura verificando constraints"""
        try:
            # Verificar si es super admin
            if user_id in SUPER_ADMIN_IDS:
                raise ValueError("No se puede eliminar a un super administrador")
            
            # Verificar si es admin
            is_admin = self.execute_query(
                "SELECT is_admin FROM users WHERE id = %s AND is_admin = TRUE",
                (user_id,)
            )
            
            if is_admin:
                raise ValueError("No se puede eliminar a un administrador. Usa /deladmin primero")
            
            # Verificar si el usuario existe
            user_exists = self.execute_query("SELECT id FROM users WHERE id = %s", (user_id,))
            
            if not user_exists:
                raise ValueError(f"Usuario {user_id} no encontrado")
            
            # Con CASCADE correctamente configurado, esto debería funcionar automáticamente
            result = self.execute_query("DELETE FROM users WHERE id = %s", (user_id,))
            
            if result > 0:
                logger.info(f"✅ Usuario {user_id} eliminado correctamente con todos sus registros relacionados")
                return True
            else:
                raise ValueError(f"No se pudo eliminar el usuario {user_id}")
                
        except Exception as e:
            logger.error(f"❌ Error eliminando usuario {user_id}: {e}")
            raise

    def block_user(self, user_id, reason, email_involved=None):
        """Bloquea a un usuario y cierra automáticamente sus sesiones web"""
        try:
            # 1. Bloquear usuario
            self.execute_query("""
                UPDATE users SET is_blocked = TRUE, blocked_reason = %s, blocked_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (reason, user_id))
            
            logger.info(f"✅ Usuario {user_id} bloqueado por: {reason}")
            
            # 2. Cerrar automáticamente todas las sesiones web activas del usuario
            sessions_closed = self.execute_query("""
                UPDATE web_sessions 
                SET is_active = FALSE 
                WHERE user_id = %s AND is_active = TRUE
            """, (user_id,))
            
            if sessions_closed > 0:
                logger.info(f"🔒 {sessions_closed} sesiones web cerradas automáticamente para usuario {user_id}")
            
            if email_involved:
                logger.info(f"📧 Email involucrado: {email_involved}")
                
        except Exception as e:
            logger.error(f"❌ Error bloqueando usuario {user_id}: {e}")

    def get_system_stats(self):
        """Obtiene estadísticas del sistema para logging"""
        try:
            stats = {}
            
            # Contar usuarios por tipo
            user_stats = self.execute_query("""
                SELECT 
                    COUNT(*) as total_users,
                    COUNT(CASE WHEN is_admin = TRUE AND id = ANY(%s) THEN 1 END) as super_admins,
                    COUNT(CASE WHEN is_admin = TRUE AND id != ALL(%s) THEN 1 END) as normal_admins,
                    COUNT(CASE WHEN is_admin = FALSE THEN 1 END) as normal_users,
                    COUNT(CASE WHEN is_blocked = TRUE THEN 1 END) as blocked_users,
                    COUNT(CASE WHEN free_access = TRUE THEN 1 END) as free_access_users
                FROM users
            """, (SUPER_ADMIN_IDS, SUPER_ADMIN_IDS))
            
            if user_stats:
                stats.update(user_stats[0])
            
            # Contar emails y configuraciones
            misc_stats = self.execute_query("""
                SELECT 
                    (SELECT COUNT(*) FROM user_emails) as total_emails,
                    (SELECT COUNT(*) FROM imap_configs) as imap_configs,
                    (SELECT COUNT(*) FROM disney_searches) as disney_searches,
                    (SELECT COUNT(*) FROM web_sessions WHERE is_active = TRUE) as active_sessions
            """)
            
            if misc_stats:
                stats.update(misc_stats[0])
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Error obteniendo estadísticas del sistema: {e}")
            return {}

    def cleanup_orphaned_records(self):
        """✅ NUEVO: Limpia registros huérfanos que podrían existir antes de aplicar CASCADE"""
        try:
            logger.info("🧹 Limpiando registros huérfanos...")

            # Limpiar búsquedas Disney huérfanas
            orphaned_searches = self.execute_query("""
                DELETE FROM disney_searches
                WHERE user_id NOT IN (SELECT id FROM users)
            """)

            if orphaned_searches > 0:
                logger.info(f"🧹 {orphaned_searches} búsquedas Disney huérfanas eliminadas")

            # Limpiar verificaciones huérfanas
            orphaned_verifications = self.execute_query("""
                DELETE FROM email_change_verifications
                WHERE user_id NOT IN (SELECT id FROM users)
                   OR search_id NOT IN (SELECT id FROM disney_searches)
            """)

            if orphaned_verifications > 0:
                logger.info(f"🧹 {orphaned_verifications} verificaciones huérfanas eliminadas")

            # Limpiar sesiones web huérfanas (aunque deberían tener CASCADE)
            orphaned_sessions = self.execute_query("""
                DELETE FROM web_sessions
                WHERE user_id NOT IN (SELECT id FROM users)
            """)

            if orphaned_sessions > 0:
                logger.info(f"🧹 {orphaned_sessions} sesiones web huérfanas eliminadas")

            logger.info("Limpieza de registros huérfanos completada")

        except Exception as e:
            logger.error(f"❌ Error limpiando registros huérfanos: {e}")

    def has_active_search(self, user_id):
        """CORREGIDO: Verifica si el usuario tiene una búsqueda activa con timestamp correcto"""
        try:
            # SOLUCIÓN DEFINITIVA: Forzar conversión explícita a UTC
            # Usar AT TIME ZONE 'UTC' para asegurar que el timestamp siempre se devuelva en UTC
            result = self.execute_query("""
                SELECT id, email,
                       (started_at AT TIME ZONE 'UTC') as started_at,
                       status, source
                FROM active_search_requests
                WHERE user_id = %s
            """, (user_id,))

            if result:
                # CRÍTICO: Convertir el timestamp de PostgreSQL a datetime timezone-aware UTC
                search = dict(result[0])
                if search['started_at']:
                    # Forzar timezone UTC ya que AT TIME ZONE 'UTC' devuelve sin timezone
                    from datetime import timezone
                    if search['started_at'].tzinfo is None:
                        search['started_at'] = search['started_at'].replace(tzinfo=timezone.utc)
                    else:
                        # Si tiene timezone, convertir a UTC
                        search['started_at'] = search['started_at'].astimezone(timezone.utc)
                return search

            return None

        except Exception as e:
            logger.error(f"❌ Error verificando búsqueda activa: {e}")
            return None

    def start_search_request(self, user_id, email, source='telegram'):
        """CORREGIDO: Registra el inicio de una búsqueda con timestamp UTC"""
        try:
            # CRÍTICO: Verificar si hay búsqueda activa DENTRO de la transacción
            # para evitar race conditions
            active = self.has_active_search(user_id)
            if active:
                logger.warning(f"⚠️ Usuario {user_id} ya tiene búsqueda activa - rechazando nueva búsqueda")
                return False

            # CORREGIDO: Usar INSERT sin ON CONFLICT para evitar sobrescribir búsquedas activas
            # Si falla por duplicado, significa que hay una búsqueda activa (race condition)
            try:
                self.execute_query("""
                    INSERT INTO active_search_requests (user_id, email, source, status, started_at)
                    VALUES (%s, %s, %s, %s, NOW() AT TIME ZONE 'UTC')
                """, (user_id, email, source, 'processing'))

                logger.info(f"🔍 Búsqueda iniciada para usuario {user_id} - Email: {email}")
                return True

            except Exception as insert_error:
                # Si falla por constraint unique, significa que ya hay búsqueda activa
                if 'unique' in str(insert_error).lower() or 'duplicate' in str(insert_error).lower():
                    logger.warning(f"⚠️ Usuario {user_id} intentó iniciar búsqueda duplicada (race condition)")
                    return False
                else:
                    # Otro error - propagar
                    raise

        except Exception as e:
            logger.error(f"❌ Error iniciando búsqueda: {e}")
            return False

    def end_search_request(self, user_id):
        """NUEVO: Finaliza una búsqueda activa"""
        try:
            result = self.execute_query("""
                DELETE FROM active_search_requests
                WHERE user_id = %s
            """, (user_id,))

            if result > 0:
                logger.info(f"Búsqueda finalizada para usuario {user_id}")

            return result > 0

        except Exception as e:
            logger.error(f"❌ Error finalizando búsqueda: {e}")
            return False

    def cleanup_stale_requests(self, timeout_minutes=10):
        """NUEVO: Limpia búsquedas que llevan demasiado tiempo (safety mechanism)"""
        try:
            # ✅ AUDIT: Query parametrizada en vez de f-string para prevenir SQL injection
            result = self.execute_query("""
                DELETE FROM active_search_requests
                WHERE started_at < NOW() - make_interval(mins := %s)
            """, (timeout_minutes,))

            if result > 0:
                logger.warning(f"🧹 {result} búsquedas obsoletas limpiadas (timeout: {timeout_minutes} min)")

            return result

        except Exception as e:
            logger.error(f"❌ Error limpiando búsquedas obsoletas: {e}")
            return 0

    def cleanup_all_active_searches(self):
        """NUEVO: Limpia TODAS las búsquedas activas (usar solo para mantenimiento)"""
        try:
            result = self.execute_query("DELETE FROM active_search_requests")
            if result > 0:
                logger.info(f"🧹 {result} búsquedas activas limpiadas completamente")
            return result
        except Exception as e:
            logger.error(f"❌ Error limpiando todas las búsquedas: {e}")
            return 0

    def save_otp(self, user_id, otp_code, expiry_minutes=5):
        """Guarda un código OTP para un usuario con tiempo de expiración"""
        try:
            # Eliminar códigos anteriores del usuario
            deleted = self.execute_query(
                "DELETE FROM verification_codes WHERE user_id = %s",
                (user_id,)
            )

            if deleted > 0:
                logger.info(f"🗑️ {deleted} códigos OTP anteriores eliminados para usuario {user_id}")

            # Insertar nuevo código (asegurar que sea string)
            # ✅ AUDIT: Query parametrizada en vez de f-string
            otp_code_str = str(otp_code).strip()
            self.execute_query("""
                INSERT INTO verification_codes (user_id, code, expires_at)
                VALUES (%s, %s, NOW() + make_interval(mins := %s))
            """, (user_id, otp_code_str, expiry_minutes))

            # Obtener el expires_at para logging
            result = self.execute_query("""
                SELECT expires_at FROM verification_codes
                WHERE user_id = %s AND code = %s
            """, (user_id, otp_code_str))

            expires_at = result[0]['expires_at'] if result else "desconocido"
            # ✅ SECURITY: Never log OTP codes in production
            logger.info(f"🔐 OTP guardado para usuario {user_id} (expira: {expires_at})")
            return True

        except Exception as e:
            logger.error(f"❌ Error guardando OTP: {e}")
            return False

    def verify_otp(self, user_id, otp_code):
        """Verifica un código OTP y lo elimina si es válido.

        ✅ FIX #2 — Operación atómica con DELETE ... RETURNING.
        Elimina la race condition del patrón SELECT + DELETE separado.
        Solo una request concurrente puede eliminar la fila y recibir RETURNING;
        cualquier request paralela no encontrará fila y recibirá False.
        """
        conn = None
        cursor = None
        try:
            # Normalizar el código OTP recibido
            otp_code_str = str(otp_code).strip()

            # ✅ SECURITY: Minimal logging - no OTP codes in production logs
            logger.info(f"🔍 Verificando OTP para usuario {user_id}")

            # ✅ FIX #2: DELETE ... RETURNING atómico.
            # Valida user_id, code y expires_at > NOW() en la MISMA sentencia que elimina.
            # Si la fila existe y es válida  → la elimina y devuelve su id (OTP consumido).
            # Si no existe, ya expiró o fue consumida por otro request → no devuelve fila.
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM verification_codes
                WHERE user_id = %s
                  AND code = %s
                  AND expires_at > NOW()
                RETURNING id
            """, (user_id, otp_code_str))

            deleted_row = cursor.fetchone()
            conn.commit()

            if not deleted_row:
                # OTP inválido, expirado o ya consumido por request concurrente
                logger.warning(f"⚠️ OTP inválido, expirado o ya consumido para usuario {user_id}")
                return False

            logger.info(f"✅ OTP verificado y consumido atómicamente para usuario {user_id}")
            return True

        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            logger.error(f"❌ Error verificando OTP: {e}")
            return False
        finally:
            if cursor:
                try:
                    cursor.close()
                except Exception:
                    pass
            if conn:
                self.put_connection(conn)

    def cleanup_expired_otps(self):
        """Limpia códigos OTP expirados (llamar periódicamente)"""
        try:
            result = self.execute_query("""
                DELETE FROM verification_codes
                WHERE expires_at < NOW()
            """)

            if result > 0:
                logger.info(f"🧹 {result} códigos OTP expirados eliminados")

            return result

        except Exception as e:
            logger.error(f"❌ Error limpiando OTPs expirados: {e}")
            return 0

    def get_user_emails_debug(self, user_id):
        """DEBUGGING: Obtiene todos los emails asignados a un usuario para diagnóstico"""
        try:
            emails = self.execute_query(
                "SELECT id, user_id, email, created_at FROM user_emails WHERE user_id = %s ORDER BY email",
                (user_id,)
            )

            if emails:
                logger.info(f"🔍 DEBUG - Usuario {user_id} tiene {len(emails)} emails:")
                for email_record in emails:
                    logger.info(f"   📧 ID: {email_record['id']}, Email: {email_record['email']}, Creado: {email_record['created_at']}")
            else:
                logger.warning(f"⚠️ DEBUG - Usuario {user_id} NO tiene emails asignados en la tabla user_emails")

            return emails

        except Exception as e:
            logger.error(f"❌ Error obteniendo emails para debug: {e}")
            return None

    # ✅ NEW: Secure IMAP configuration methods with encryption
    def save_imap_config_secure(self, domain, email, password, server, created_by):
        """
        ✅ SECURE: Save IMAP configuration with encrypted password
        """
        try:
            # Encrypt password before storing
            encrypted_password = encrypt_password(password)

            self.execute_query("""
                INSERT INTO imap_configs (domain, email, password, server, created_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (domain) DO UPDATE SET
                email = EXCLUDED.email,
                password = EXCLUDED.password,
                server = EXCLUDED.server,
                created_by = EXCLUDED.created_by
            """, (domain, email, encrypted_password, server, created_by))

            logger.info(f"✅ IMAP config saved securely for domain: {domain}")
            return True

        except Exception as e:
            logger.error(f"❌ Error saving IMAP config: {e}")
            return False

    def get_imap_config_secure(self, domain):
        """
        ✅ SECURE: Get IMAP configuration with decrypted password.
        Returns: dict with password decrypted in memory, or None.

        ✅ FIX #3 — Migración on-read tolerante para passwords legacy:
        Si la password en BD no está cifrada (formato Fernet), se usa en claro
        para esta sesión y se cifra+actualiza en BD automáticamente.
        Nunca se loguea la password (ni cifrada ni en claro).
        """
        try:
            result = self.execute_query(
                "SELECT domain, email, password, server, port FROM imap_configs WHERE domain = %s",
                (domain,)
            )

            if not result:
                return None

            config = dict(result[0])
            raw_password = config['password']

            # ── Detección de formato ────────────────────────────────────────
            # Las passwords cifradas con Fernet comienzan siempre con 'gAAAAA'
            # (base64url de los primeros bytes del token Fernet v1).
            is_encrypted = raw_password.startswith('gAAAAA') or raw_password.startswith('Z0FBQ')

            if is_encrypted:
                # Password ya cifrada → descifrar normalmente
                try:
                    config['password'] = decrypt_password(raw_password)
                    logger.debug(f"🔓 IMAP config decrypted for domain: {domain}")
                except Exception as decrypt_error:
                    # Si falla el descifrado de una password que parece cifrada,
                    # es probable que la clave haya cambiado → error crítico
                    logger.error(f"❌ Failed to decrypt IMAP password for {domain}: {decrypt_error}")
                    raise ValueError(
                        f"Password decryption failed for {domain}. "
                        "Encryption key may have changed. Re-add the IMAP config with /addimap."
                    )
            else:
                # Password legacy en texto plano → migración on-read
                logger.warning(
                    f"⚠️ IMAP config for '{domain}' has a plaintext password (legacy). "
                    "Migrating to encrypted format automatically."
                )
                # Usamos la password en claro para esta sesión
                config['password'] = raw_password

                # Cifrar y actualizar en BD de forma silenciosa (best-effort)
                try:
                    encrypted = encrypt_password(raw_password)
                    self.execute_query(
                        "UPDATE imap_configs SET password = %s WHERE domain = %s",
                        (encrypted, domain)
                    )
                    logger.info(f"✅ IMAP password for '{domain}' migrated to encrypted format.")
                except Exception as migrate_error:
                    # No bloqueamos la operación si la migración falla; solo logueamos
                    logger.error(f"❌ Could not auto-migrate IMAP password for '{domain}': {migrate_error}")

            return config

        except Exception as e:
            logger.error(f"❌ Error getting IMAP config for '{domain}': {e}")
            return None

    def migrate_imap_passwords_to_encrypted(self):
        """
        ✅ MIGRATION: Encrypt existing plaintext IMAP passwords
        Run this once to migrate existing data
        """
        try:
            logger.info("🔧 Starting IMAP password encryption migration...")

            # Get all IMAP configs
            configs = self.execute_query("SELECT domain, password FROM imap_configs")

            if not configs:
                logger.info("ℹ️ No IMAP configs to migrate")
                return 0

            migrated = 0
            for config in configs:
                domain = config['domain']
                password = config['password']

                # Check if already encrypted (Fernet encrypted strings start with 'gAAAAA')
                if password.startswith('gAAAAA') or password.startswith('Z0FBQ'):
                    logger.debug(f"⏭️ Skipping {domain} - already encrypted")
                    continue

                try:
                    # Encrypt the plaintext password
                    encrypted_password = encrypt_password(password)

                    # Update in database
                    self.execute_query(
                        "UPDATE imap_configs SET password = %s WHERE domain = %s",
                        (encrypted_password, domain)
                    )

                    migrated += 1
                    logger.info(f"✅ Migrated password for domain: {domain}")

                except Exception as e:
                    logger.error(f"❌ Failed to migrate {domain}: {e}")
                    continue

            logger.info(f"✅ Migration completed: {migrated} passwords encrypted")
            return migrated

        except Exception as e:
            logger.error(f"❌ Migration error: {e}")
            return 0

    def create_performance_indexes(self):
        """✅ AUDIT: Crea índices de rendimiento para consultas de alta concurrencia"""
        logger.info("🔧 Creando índices de rendimiento...")

        indexes = [
            # Índices para sesiones web (consultadas en CADA request autenticado)
            "CREATE INDEX IF NOT EXISTS idx_web_sessions_token ON web_sessions(session_token) WHERE is_active = TRUE",
            "CREATE INDEX IF NOT EXISTS idx_web_sessions_user_active ON web_sessions(user_id, is_active)",

            # Índices para emails de usuario (verificación de permisos frecuente)
            "CREATE INDEX IF NOT EXISTS idx_user_emails_user_email ON user_emails(user_id, LOWER(email))",

            # Índices para búsquedas Disney (conteos frecuentes)
            "CREATE INDEX IF NOT EXISTS idx_disney_searches_user ON disney_searches(user_id, search_date DESC)",

            # Índices para códigos de verificación (verificación OTP)
            "CREATE INDEX IF NOT EXISTS idx_verification_codes_user ON verification_codes(user_id, expires_at)",

            # Índice para usuarios bloqueados (filtrado rápido)
            "CREATE INDEX IF NOT EXISTS idx_users_blocked ON users(is_blocked) WHERE is_blocked = TRUE",

            # Índice para búsquedas activas
            "CREATE INDEX IF NOT EXISTS idx_active_search_user ON active_search_requests(user_id)",
        ]

        for index_sql in indexes:
            try:
                self.execute_query(index_sql)
            except Exception as e:
                logger.warning(f"⚠️ Error creando índice de rendimiento: {e}")

        logger.info("✅ Índices de rendimiento creados/verificados")

    def close_pool(self):
        """✅ AUDIT: Cierra el pool de conexiones de forma ordenada"""
        try:
            if self.pool and not self.pool.closed:
                self.pool.closeall()
                logger.info("✅ Pool de conexiones cerrado")
        except Exception as e:
            logger.error(f"❌ Error cerrando pool: {e}")


# Instancia global
db = Database()
