#!/bin/bash
set -euo pipefail

# === VARIABLES EXACTAS ===
REPO_URL="https://github.com/Cin3t3ch7/Dis.git"
BRANCH="main" # Cámbialo aquí a "master" si en tu GitHub la rama dice master
APP_DIR="/home/disneyuser/disney-search-pro"
VENV_DIR="$APP_DIR/venv"
SERVICE_NAME="disney-search.service"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="${APP_DIR}_backup_${TIMESTAMP}"

echo "======================================================="
echo "[INFO] Iniciando despliegue de $SERVICE_NAME"
echo "======================================================="

# 1. Validar systemctl y servicio
if ! command -v systemctl &> /dev/null; then
    echo "[ERROR] systemctl no está disponible."
    exit 1
fi

if ! systemctl list-unit-files | grep "^${SERVICE_NAME}" > /dev/null; then
    echo "[ERROR] El servicio $SERVICE_NAME no existe."
    exit 1
fi

# 2. Respaldo del proyecto (excluyendo venv y logs de disney_search)
if [ -d "$APP_DIR" ]; then
    echo "[INFO] Empaquetando backup en $BACKUP_DIR.tar.gz..."
    tar --exclude="$VENV_DIR" \
        --exclude="$APP_DIR/logs" \
        --exclude="$APP_DIR/disney_search.log" \
        --exclude="$APP_DIR/.git" \
        -czf "${BACKUP_DIR}.tar.gz" "$APP_DIR" 2>/dev/null || echo "[WARN] Backup completado con advertencias menores."
fi

# 3. Detener servicio
echo "[INFO] Deteniendo $SERVICE_NAME..."
systemctl stop "$SERVICE_NAME"

# 4. Solución al problema de permisos (root vs disneyuser detectado)
echo "[INFO] Configurando permisos de Git..."
git config --global --add safe.directory "$APP_DIR"

# 5. Actualizar código desde GitHub
echo "[INFO] Descargando la última versión del código fuente..."
if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR"
    git remote set-url origin "$REPO_URL" || git remote add origin "$REPO_URL"
    git fetch origin --prune
    git reset --hard "origin/$BRANCH"
else
    echo "[WARN] No es un repositorio Git válido. Moviendo a backup y clonando..."
    mv "$APP_DIR" "${APP_DIR}_old_${TIMESTAMP}" 
    git clone -b "$BRANCH" "$REPO_URL" "$APP_DIR"
    cd "$APP_DIR"
    git config --global --add safe.directory "$APP_DIR"
fi

# 6. Gestión segura de variables de entorno (NUNCA pisar el local)
echo "[INFO] Verificando secretos y .env..."
if [ -f "$APP_DIR/.env" ]; then
    echo "[INFO] .env detectado correctamente en la VPS."
else
    if [ -f "$APP_DIR/.env.example" ]; then
        cp "$APP_DIR/.env.example" "$APP_DIR/.env"
        echo "[ERROR] No había .env local. Se creó uno desde .env.example."
        echo "        DEBES EDITAR $APP_DIR/.env antes de levantar el servicio."
        exit 1
    fi
fi

# 7. Entorno virtual y dependencias
echo "[INFO] Configurando Python VENV y librerías..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# Reparar permisos para que disneyuser pueda leer todo si root lo modificó
chown -R disneyuser:disneyuser "$APP_DIR"
# Pero devolver la propiedad del root a los configs clave si así los tenías
chown root:root "$APP_DIR/.env" 2>/dev/null || true

# 8. Encender servicio
echo "[INFO] Iniciando $SERVICE_NAME..."
systemctl daemon-reload
systemctl start "$SERVICE_NAME"
systemctl enable "$SERVICE_NAME"

# 9. Verificación Final
echo "======================================================="
echo "[INFO] DESPLIEGUE FINALIZADO. Estado del servicio:"
systemctl status --no-pager "$SERVICE_NAME" | grep -E "Active:|Main PID:"
echo "-------------------------------------------------------"
echo "[INFO] Últimas líneas del log del servicio:"
journalctl -u "$SERVICE_NAME" -n 10 --no-pager
echo "======================================================="
