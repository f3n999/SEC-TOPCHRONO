#!/bin/bash
# ============================================
# DEPLOY - Phishing Detection Server
# Machine cible : 192.168.237.133
# ============================================
set -e

echo "========================================"
echo "  INSTALLATION PHISHING DETECTION SERVER"
echo "========================================"

# 1) Mise a jour systeme
echo "[1/5] Mise a jour du systeme..."
sudo apt update -y && sudo apt upgrade -y

# 2) Installer Python et pip
echo "[2/5] Installation de Python..."
sudo apt install -y python3 python3-pip python3-venv

# 3) Creer le repertoire du projet
echo "[3/5] Configuration du projet..."
PROJECT_DIR="/opt/phishing-server"
sudo mkdir -p $PROJECT_DIR
sudo chown $USER:$USER $PROJECT_DIR

# 4) Environnement virtuel + dependances
echo "[4/5] Installation des dependances..."
cd $PROJECT_DIR
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn pydantic

# 5) Copier server.py (doit etre dans le meme dossier que ce script)
if [ -f "$(dirname "$0")/server.py" ]; then
    cp "$(dirname "$0")/server.py" $PROJECT_DIR/server.py
    echo "  [OK] server.py copie."
else
    echo "  [!] server.py non trouve a cote du script. Copie-le manuellement dans $PROJECT_DIR/"
fi

# 6) Creer le service systemd
echo "[5/5] Creation du service systemd..."
sudo tee /etc/systemd/system/phishing-server.service > /dev/null << EOF
[Unit]
Description=Phishing Detection API Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$PROJECT_DIR
Environment=DB_PATH=$PROJECT_DIR/phishing_agent.db
ExecStart=$PROJECT_DIR/venv/bin/python $PROJECT_DIR/server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable phishing-server
sudo systemctl start phishing-server

echo ""
echo "========================================"
echo "  INSTALLATION TERMINEE"
echo "========================================"
echo ""
echo "  Serveur    : http://192.168.237.133:8000"
echo "  API Docs   : http://192.168.237.133:8000/docs"
echo "  Health     : http://192.168.237.133:8000/api/health"
echo "  Stats      : http://192.168.237.133:8000/api/stats"
echo "  Base       : $PROJECT_DIR/phishing_agent.db"
echo ""
echo "  Commandes utiles :"
echo "    sudo systemctl status phishing-server"
echo "    sudo systemctl restart phishing-server"
echo "    sudo journalctl -u phishing-server -f"
echo ""
