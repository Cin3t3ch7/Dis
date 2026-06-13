#!/bin/bash
# Script de Despliegue Automático para Disney Search Pro
# Ejecutar con privilegios sudo o como root.

set -e

echo "=========================================================="
echo "🚀 INICIANDO INSTALACIÓN DE DISNEY SEARCH PRO EN UBUNTU VPS"
echo "=========================================================="

APP_DIR="/var/www/disney-search-pro"
DOMAIN="Dthenxx.online"
DB_NAME="disney_search_db"
DB_USER="disney_admin"

# Solicitar inputs del usuario
read -p "Introduce la contraseña deseada para PostgreSQL (disney_admin): " DB_PASSWORD
read -p "¿Tienes apuntado ya el dominio $DOMAIN a la IP de este servidor? (s/n): " DNS_READY

echo "Actualizando el sistema e instalando dependencias..."
apt update && apt upgrade -y
apt install -y python3 python3-venv python3-pip git postgresql postgresql-contrib nginx certbot python3-certbot-nginx curl

echo "=========================================================="
echo "🗄️ CONFIGURANDO POSTGRESQL"
echo "=========================================================="
# Crear usuario y base de datos (ignora errores si ya existen)
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" || true
sudo -u postgres psql -c "CREATE USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';" || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" || true
sudo -u postgres psql -c "ALTER DATABASE $DB_NAME OWNER TO $DB_USER;" || true
sudo -u postgres psql -d $DB_NAME -c "GRANT ALL ON SCHEMA public TO $DB_USER;" || true

echo "=========================================================="
echo "📁 CONFIGURANDO EL PROYECTO"
echo "=========================================================="
if [ ! -d "$APP_DIR" ]; then
    echo "Clonando repositorio desde GitHub..."
    mkdir -p /var/www
    cd /var/www
    # Si el repo es privado, te pedirá credenciales (Username y Personal Access Token de GitHub)
    git clone https://github.com/Cin3t3ch7/Dis disney-search-pro
fi

cd "$APP_DIR"

# Crear y activar entorno virtual
echo "Creando entorno virtual e instalando requisitos..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Configurar .env si no existe
if [ ! -f ".env" ]; then
    echo "Creando archivo .env a partir de .env.example..."
    cp .env.example .env
    
    # Generar cadena de conexión de BD
    DB_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost/$DB_NAME"
    sed -i "s|DATABASE_URL=.*|DATABASE_URL=$DB_URL|g" .env
    
    # Generar Secret Key si no existe
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    sed -i "s|SECRET_KEY=.*|SECRET_KEY=$SECRET_KEY|g" .env
    
    echo "⚠️ IMPORTANTE: Recuerda editar /var/www/disney-search-pro/.env para colocar tu BOT_TOKEN y SUPER_ADMIN_IDS."
fi

echo "=========================================================="
echo "⚙️  CONFIGURANDO SERVICIO SYSTEMD (BACKGROUND)"
echo "=========================================================="
cat > /etc/systemd/system/disney.service <<EOF
[Unit]
Description=Disney Search Pro Service
After=network.target postgresql.service

[Service]
User=root
Group=www-data
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/python main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable disney
systemctl start disney
echo "Servicio Disney Search Pro iniciado y habilitado."

echo "=========================================================="
echo "🌐 CONFIGURANDO NGINX (PROXY INVERSO)"
echo "=========================================================="
cat > /etc/nginx/sites-available/disney <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Habilitar el sitio
ln -s /etc/nginx/sites-available/disney /etc/nginx/sites-enabled/ 2>/dev/null || true
rm -f /etc/nginx/sites-enabled/default

# Probar y reiniciar Nginx
nginx -t
systemctl restart nginx

echo "=========================================================="
echo "🔒 CONFIGURANDO CERTIFICADO SSL (CERTBOT)"
echo "=========================================================="
if [ "$DNS_READY" == "s" ] || [ "$DNS_READY" == "S" ] || [ "$DNS_READY" == "y" ]; then
    echo "Solicitando certificado SSL para $DOMAIN y www.$DOMAIN..."
    certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m admin@$DOMAIN --redirect
    echo "¡Certificado SSL instalado correctamente!"
else
    echo "Has indicado que el DNS no está listo. Ejecuta certbot manualmente luego:"
    echo "sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN"
fi

echo "=========================================================="
echo "✅ ¡INSTALACIÓN COMPLETADA EXITOSAMENTE! ✅"
echo "=========================================================="
echo "-> Edita tus credenciales: nano $APP_DIR/.env"
echo "-> Reinicia tu app si editas el .env: systemctl restart disney"
echo "-> Revisa los logs en caso de error: journalctl -u disney -f"
echo "-> Accede a tu web en: https://$DOMAIN"
