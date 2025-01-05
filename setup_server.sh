#!/bin/bash

# Obter o usuário atual
CURRENT_USER=$SUDO_USER
clear

# Função de barra de progresso genérica
progress_bar() {
    local current_step=$1
    local total_steps=$2
    local bar_width=$3
    local description=$4

    local progress=$((current_step * 100 / total_steps))
    local filled=$((progress * bar_width / 100))
    local empty=$((bar_width - filled))

    local filled_bar=$(printf "%0.s#" $(seq 1 "$filled"))
    local empty_bar=$(printf "%0.s." $(seq 1 "$empty"))

    printf "\r%s [%s%s] %3d%% (%d/%d)" "$description" "$filled_bar" "$empty_bar" "$progress" "$current_step" "$total_steps"
}

# --- Bloco 1: Remoção de Pacotes ---
INSTALLED_PACKAGES=(
    "apt-transport-https"
    "curl"
    "ufw"
    "fail2ban"
    "chrony"
    "samba"
    "git"
    "cron"
    "inetutils-ping"
    "file"
    "clamav"
    "clamav-daemon"
    "ldap-utils"
    "libldap2-dev"
    "squid-openssl"
    "btop"
    "unzip"
    "unattended-upgrades"
    "apt-listchanges"
    "squid"
)

TOTAL_PACKAGES=${#INSTALLED_PACKAGES[@]}
CURRENT_STEP=0
BAR_WIDTH=50

echo -e "\e[32m[REMOVENDO PACOTES]\e[0m"
for PACKAGE in "${INSTALLED_PACKAGES[@]}"; do
    if dpkg -l | awk '$1=="ii" && $2=="'$PACKAGE'" {print}' > /dev/null; then
        sudo apt remove --purge -y "$PACKAGE" > /dev/null 2>&1
    fi
    CURRENT_STEP=$((CURRENT_STEP + 1))
    progress_bar "$CURRENT_STEP" "$TOTAL_PACKAGES" "$BAR_WIDTH" "Removendo pacotes"
done
echo -e "\nRemoção de pacotes concluída!"

# --- Bloco 2: Remoção de Diretórios ---
CONFIG_DIRS=(
    "/etc/squid/ssl_cert"
    "/var/log/squid"
    "/var/lib/samba"
)

TOTAL_DIRS=${#CONFIG_DIRS[@]}
CURRENT_STEP=0
DIR_BAR_WIDTH=50

echo -e "\e[32m[REMOVENDO DIRETÓRIOS]\e[0m"
for DIR in "${CONFIG_DIRS[@]}"; do
    if [ -d "$DIR" ]; then
        sudo rm -rf "$DIR"
    fi
    CURRENT_STEP=$((CURRENT_STEP + 1))
    progress_bar "$CURRENT_STEP" "$TOTAL_DIRS" "$DIR_BAR_WIDTH" "Removendo diretórios"
done
echo -e "\nRemoção de diretórios concluída!"

# --- Bloco 3: Limpeza de Pacotes ---
TOTAL_CLEAN_STEPS=2
CURRENT_STEP=0
CLEAN_BAR_WIDTH=50

echo -e "\e[32m[LIMPEZA DE PACOTES]\e[0m"
sudo apt autoremove -y > /dev/null 2>&1
CURRENT_STEP=$((CURRENT_STEP + 1))
progress_bar "$CURRENT_STEP" "$TOTAL_CLEAN_STEPS" "$CLEAN_BAR_WIDTH" "Autoremove"

sudo apt autoclean -y > /dev/null 2>&1
CURRENT_STEP=$((CURRENT_STEP + 1))
progress_bar "$CURRENT_STEP" "$TOTAL_CLEAN_STEPS" "$CLEAN_BAR_WIDTH" "Autoclean"
echo -e "\nLimpeza de pacotes concluída!"

# --- Bloco 4: Instalação de Pacotes ---
INSTALL_PACKAGES=(
    "apt-transport-https"
    "curl"
    "ufw"
    "fail2ban"
    "chrony"
    "samba"
    "git"
    "cron"
    "inetutils-ping"
    "file"
    "clamav"
    "clamav-daemon"
    "ldap-utils"
    "libldap2-dev"
    "squid-openssl"
    "btop"
    "unzip"
)

TOTAL_INSTALL_PACKAGES=${#INSTALL_PACKAGES[@]}
CURRENT_STEP=0
INSTALL_BAR_WIDTH=50

echo -e "\e[32m[INSTALAÇÃO DE PACOTES]\e[0m"
for PACKAGE in "${INSTALL_PACKAGES[@]}"; do
    sudo apt install -y "$PACKAGE" > /dev/null 2>&1
    CURRENT_STEP=$((CURRENT_STEP + 1))
    progress_bar "$CURRENT_STEP" "$TOTAL_INSTALL_PACKAGES" "$INSTALL_BAR_WIDTH" "Instalando pacotes"
done
echo -e "\nInstalação de pacotes concluída!"

# --- Bloco 5: Configuração do Fail2Ban ---
echo -e "\e[32m[CONFIGURAÇÃO DO FAIL2BAN]\e[0m"
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = 22

[samba]
enabled = true
port = 445
logpath = /var/log/samba/*.log

[squid]
enabled = true
port = 3128
logpath = /var/log/squid/access.log
maxretry = 10
findtime = 600
bantime = 3600
EOF
sudo systemctl restart fail2ban
echo -e "\nConfiguração do Fail2Ban concluída!"

# --- Bloco 6: Configuração de Diretórios ---
CONFIG_DIRS=(
    "/var/suporte"
    "/var/WUCache"
)

TOTAL_DIRS=${#CONFIG_DIRS[@]}
CURRENT_STEP=0
DIR_BAR_WIDTH=50

echo -e "\e[32m[CONFIGURAÇÃO DE DIRETÓRIOS]\e[0m"
for DIR in "${CONFIG_DIRS[@]}"; do
    sudo mkdir -p "$DIR" > /dev/null 2>&1
    sudo chmod 777 "$DIR"
    CURRENT_STEP=$((CURRENT_STEP + 1))
    progress_bar "$CURRENT_STEP" "$TOTAL_DIRS" "$DIR_BAR_WIDTH" "Configurando diretórios"
done
echo -e "\nConfiguração de diretórios concluída!"

# --- Bloco 7: Configuração do WSUS Offline ---
echo -e "\e[32m[CONFIGURAÇÃO DO WSUS OFFLINE]\e[0m"
cd /var/WUCache
if [ ! -d "wsusoffline" ]; then
    git clone https://gitlab.com/wsusoffline/wsusoffline.git
fi
chown $CURRENT_USER:$CURRENT_USER -Rf wsusoffline
cd wsusoffline/sh
chmod +x *.bash

# Configurar cron job para WSUS Offline
cron_job="0 2 * * * /bin/bash /var/WUCache/wsusoffline/sh/download-updates.bash all-win-x64 ptb -includewddefs"
if ! crontab -l | grep -Fxq "$cron_job"; then
    (crontab -l 2>/dev/null; echo "$cron_job") | crontab -
fi
echo -e "\nConfiguração do WSUS Offline concluída!"

# --- Bloco 8: Configuração de Atualizações Automáticas ---
echo -e "\e[32m[CONFIGURAÇÃO DE ATUALIZAÇÕES AUTOMÁTICAS]\e[0m"
sudo apt install -y unattended-upgrades apt-listchanges > /dev/null 2>&1
sudo dpkg-reconfigure --priority=low unattended-upgrades > /dev/null 2>&1

sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null <<EOF
Unattended-Upgrade::Allowed-Origins {
        "\${distro_id}:\${distro_codename}-security";
        "\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
echo -e "\nAtualizações automáticas configuradas!"

# --- Bloco 9: Configuração do Firewall (UFW) ---
echo -e "\e[32m[CONFIGURAÇÃO DO FIREWALL (UFW)]\e[0m"
sudo ufw default deny incoming > /dev/null 2>&1
sudo ufw default allow outgoing > /dev/null 2>&1
sudo ufw allow 22/tcp > /dev/null 2>&1
sudo ufw allow 3128/tcp > /dev/null 2>&1
sudo ufw allow from 10.60.9.0/24 to any port 445 > /dev/null 2>&1
sudo ufw allow proto udp from 10.60.9.0/24 to any port 137,138,139 > /dev/null 2>&1
sudo ufw allow 8000/tcp > /dev/null 2>&1
sudo ufw limit ssh/tcp > /dev/null 2>&1
sudo ufw logging on > /dev/null 2>&1
sudo ufw enable > /dev/null 2>&1
echo -e "\nConfiguração do firewall concluída!"

# --- Bloco 10: Instalação e Configuração do ClamAV ---
echo -e "\e[32m[INSTALAÇÃO E CONFIGURAÇÃO DO CLAMAV]\e[0m"
sudo apt install -y clamav clamav-daemon > /dev/null 2>&1
sudo systemctl stop clamav-freshclam > /dev/null 2>&1
sudo freshclam > /dev/null 2>&1
sudo systemctl start clamav-daemon > /dev/null 2>&1
sudo systemctl enable clamav-daemon > /dev/null 2>&1

# Configurar varredura de vírus periódica
echo "0 3 * * * root clamscan -r / --remove --log=/var/log/clamav/scan.log" | sudo tee -a /etc/crontab > /dev/null
echo -e "\nConfiguração do ClamAV concluída!"

# --- Bloco 11: Configuração do Samba e Squid ---
echo -e "\e[32m[CONFIGURAÇÃO DO SAMBA E SQUID]\e[0m"

# Configuração do Samba
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.bak > /dev/null 2>&1
sudo chown -R root:sambashare /var/lib/samba/usershares > /dev/null 2>&1
sudo chmod 1777 /var/lib/samba/usershares > /dev/null 2>&1

sudo tee /etc/samba/smb.conf > /dev/null <<EOF
[global]
workgroup = DEFENSORIA
server role = standalone server
netbios name = s
usershare allow guests = yes
usershare max shares = 100
usershare path = /var/lib/samba/usershares
server min protocol = SMB2
client min protocol = SMB2
preferred master = no
security = user
map to guest = Bad User
log file = /var/log/samba/%m.log
log level = 1
dns proxy = no
wins support = no
bind interfaces only = yes
#interfaces = 127.0.0.1 enp0s25

[SuporteTI]
path = /var/suporte
read only = No
browseable = Yes
guest ok = Yes
writable = Yes

[wsusoffline]
path = /var/WUCache/wsusoffline/client
browseable = yes
writable = yes
guest ok = yes
read only = no
EOF

sudo systemctl restart smbd nmbd > /dev/null 2>&1

# Configuração do Squid
sudo mkdir -p /etc/squid/certs > /dev/null 2>&1

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
    -keyout /etc/squid/certs/myproxy.key \
    -out /etc/squid/certs/myproxy.crt \
    -subj "/C=BR/ST=Estado/L=Cidade/O=Empresa/OU=TI/CN=myproxy.local" > /dev/null 2>&1

sudo bash -c 'cat /etc/squid/certs/myproxy.crt /etc/squid/certs/myproxy.key > /etc/squid/certs/myproxy.pem' > /dev/null 2>&1
sudo chown proxy:proxy -R /etc/squid/certs/ > /dev/null 2>&1
sudo chmod 600 /etc/squid/certs/* > /dev/null 2>&1

# Criar banco de dados SSL
sudo -u proxy /usr/lib/squid/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB > /dev/null 2>&1

# Criar lista branca de domínios
sudo tee /etc/squid/lista-branca.txt > /dev/null <<EOF
.whatsapp.com
.dwservice.net
.webex.com
.ciscospark.com
.wbx2.com
.webexconnect.com
.webexcontent.com
EOF

sudo chown proxy:proxy /etc/squid/lista-branca.txt > /dev/null 2>&1
sudo chmod 644 /etc/squid/lista-branca.txt > /dev/null 2>&1

sudo tee /etc/squid/squid.conf > /dev/null <<EOF
# Porta HTTP e HTTPS com SSL-Bump
http_port 3128 ssl-bump tls-cert=/etc/squid/certs/myproxy.pem tls-key=/etc/squid/certs/myproxy.key options=NO_SSLv3 generate-host-certificates=on

# ACLs para tráfego e tipos de conteúdo
acl defensoria_static url_regex -i \.(pdf|jpg|jpeg|png|gif|css|js)$
acl defensoria_dynamic url_regex -i defensoria.to.def.br/api/
acl tjto_static url_regex -i \.(pdf|jpg|jpeg|png|gif|css|js)$
acl tjto_dynamic url_regex -i tjto.jus.br/api/
acl defensoria dstdomain defensoria.to.def.br
acl tjto dstdomain tjto.jus.br
acl bypass ssl::server_name "/etc/squid/lista-branca.txt"

# SSL-Bump configurado para otimização
ssl_bump splice bypass
ssl_bump bump defensoria_static
ssl_bump bump tjto_static
ssl_bump splice defensoria_dynamic
ssl_bump splice tjto_dynamic
ssl_bump bump all

# Diretivas de cache
cache_dir rock /var/spool/squid/rock 20480  # 20 GB para cache
cache_mem 4096 MB                          # 4 GB de memória para cache
maximum_object_size 512  MB                # Tamanho máximo de objeto: 512  MB
minimum_object_size 4 KB
maximum_object_size_in_memory 1 MB         # Priorizar objetos pequenos na memória

# Atualização preditiva para Defensoria e TJTO
refresh_pattern defensoria.to.def.br 1440 90% 10080
refresh_pattern tjto.jus.br 1440 90% 10080
refresh_pattern -i \.(html|htm|json|css|js)$ 0 20% 4320
refresh_pattern -i \.(jpg|jpeg|png|gif|ico|pdf)$ 360 90% 4320

# Permissões de acesso
acl rede_permitida src 10.60.9.0/24
http_access allow rede_permitida
http_access allow rede_permitida defensoria
http_access allow rede_permitida tjto
http_access allow rede_permitida bypass
http_access deny all

# Configurações gerais
dns_v4_first on
dns_nameservers 8.8.8.8 8.8.4.4
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log

# Configurações avançadas para desempenho
collapsed_forwarding on
quick_abort_min 16 KB
quick_abort_max 16 KB
quick_abort_pct 90
vary_ignore_expire on
reload_into_ims on
range_offset_limit 0
read_ahead_gap 128 KB
tcp_recv_bufsize 256 KB
half_closed_clients off
EOF

# Ajustar permissões do diretório de cache
sudo chmod 775 -Rf /var/spool/squid/ > /dev/null 2>&1
sudo chown proxy:proxy -Rf /var/spool/squid/ > /dev/null 2>&1
sudo systemctl restart squid > /dev/null 2>&1

# Finalizando
echo -e "\nWSUS Offline configurado com sucesso. As atualizações serão baixadas e processadas automaticamente todos os dias às 02:00."
su - "$CURRENT_USER" -c "bash /var/WUCache/wsusoffline/sh/download-updates.bash all-win-x64 ptb -includewddefs" > /dev/null 2>&1