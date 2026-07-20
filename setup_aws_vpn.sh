#!/bin/bash
# ==============================================================================
# SCRIPT DE CONFIGURAÇÃO AUTOMÁTICA - CLIENT VPN AWS (KALI LINUX)
# Autor: Gustavo
# Caminho padrão do projeto: /opt/work/magno/
# ==============================================================================

# Garantir que o script está rodando como root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Por favor, execute este script como root (sudo ./setup_aws_vpn.sh)"
  exit 1
fi

echo "[*] Iniciando a preparação do ambiente AWS VPN..."

# 1. Definindo e criando a estrutura de diretórios
BASE_DIR="/opt/work/magno"
CERT_DIR="$BASE_DIR/custom_certs"
VPC_DIR="$BASE_DIR/aws-vpc"
DOWNLOADED_CONFIG="/root/Downloads/downloaded-client-config.ovpn" # ou ~/Downloads

mkdir -p "$BASE_DIR"
mkdir -p "$CERT_DIR"
mkdir -p "$VPC_DIR"

# 2. Instalação de dependências caso não existam
echo "[*] Validando dependências necessárias..."
apt update && apt install -y easy-rsa openvpn

# 3. Preparando o Easy-RSA local
echo "[*] Configurando Easy-RSA..."
if [ ! -d "$BASE_DIR/openvpn-ca" ]; then
    make-cadir "$BASE_DIR/openvpn-ca"
fi
cd "$BASE_DIR/openvpn-ca"

# Forçar a configuração de 2048 bits no arquivo vars
echo '[*] Gravando variáveis de 2048 bits...'
cat <<EOT > vars
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_REQ_COUNTRY "BR"
set_var EASYRSA_REQ_PROVINCE "SP"
set_var EASYRSA_REQ_CITY "Varzea Paulista"
set_var EASYRSA_REQ_ORG "Magno Cyber"
set_var EASYRSA_REQ_EMAIL "gustavo@magno.lan"
set_var EASYRSA_REQ_OU "IT Infrastructure"
EOT

# 4. Limpando PKI anterior e gerando a Autoridade Certificadora (CA)
echo "[*] Gerando Autoridade Certificadora (CA) de 2048 bits..."
./easyrsa init-pki
echo -e "\n" | ./easyrsa build-ca nopass

# 5. Gerando os certificados com FQDN válidos para a AWS
echo "[*] Gerando Certificado do Servidor (vpn.magno.lan)..."
./easyrsa --san=DNS:vpn.magno.lan build-server-full vpn.magno.lan nopass

echo "[*] Gerando Certificado do Cliente (client.magno.lan)..."
./easyrsa build-client-full client.magno.lan nopass

# 6. Movendo os certificados gerados para a pasta customizada
echo "[*] Organizando chaves e certificados gerados..."
cp pki/ca.crt "$CERT_DIR/ca.crt"
cp pki/issued/vpn.magno.lan.crt "$CERT_DIR/server.crt"
cp pki/private/vpn.magno.lan.key "$CERT_DIR/server.key"
cp pki/issued/client.magno.lan.crt "$CERT_DIR/client1.crt"
cp pki/private/client.magno.lan.key "$CERT_DIR/client1.key"

echo "[+] Certificados gerados com sucesso em: $CERT_DIR"
echo "[!] IMPORTANTE: Importe o 'server.crt'/'server.key' e o 'client1.crt'/'client1.key' para o AWS ACM antes de prosseguir."
echo -n "[*] Pressione ENTER após ter importado no ACM e baixado o arquivo .ovpn para seu diretório ~/Downloads... "
read -r -p ""

# 7. Localizando o arquivo baixado
if [ -f "$DOWNLOADED_CONFIG" ]; then
    cp "$DOWNLOADED_CONFIG" "$VPC_DIR/downloaded-client-config.ovpn"
elif [ -f "/home/kali/Downloads/downloaded-client-config.ovpn" ]; then
    cp "/home/kali/Downloads/downloaded-client-config.ovpn" "$VPC_DIR/downloaded-client-config.ovpn"
else
    echo "[!] Arquivo downloaded-client-config.ovpn não encontrado nas pastas de Downloads."
    echo -n "Por favor, digite o caminho completo do arquivo .ovpn: "
    read -r CUSTOM_PATH
    cp "$CUSTOM_PATH" "$VPC_DIR/downloaded-client-config.ovpn"
fi

# 8. Modificando o arquivo .ovpn para uso do OpenVPN no Kali
echo "[*] Aplicando correções de DNS e Injetando rotas/certificados no .ovpn..."
OVPN_FILE="$VPC_DIR/downloaded-client-config.ovpn"

# Corrige o '*' substituindo por 'kali' no Host do Endpoint
sed -i 's/remote \*\./remote kali\./g' "$OVPN_FILE"

# Remove declarações antigas de cert/key no arquivo se houverem
sed -i '/^cert /d' "$OVPN_FILE"
sed -i '/^key /d' "$OVPN_FILE"

# Insere os caminhos absolutos dos certificados e a rota estática para o ping.eu no final do arquivo
cat <<EOT >> "$OVPN_FILE"

# Caminhos absolutos dos certificados de 2048 bits
cert $CERT_DIR/client1.crt
key $CERT_DIR/client1.key

# Forçar o tráfego do ping.eu a sair exclusivamente pela AWS VPN
route 141.105.120.33 255.255.255.255
EOT

# 9. Configurando o OpenVPN como Serviço do Sistema (Systemd Daemon)
echo "[*] Configurando OpenVPN Systemd Service..."
sudo cp "$OVPN_FILE" "/etc/openvpn/client/aws.conf"

# Habilita e inicializa o serviço
sudo systemctl daemon-reload
sudo systemctl enable openvpn-client@aws
sudo systemctl start openvpn-client@aws

echo "=============================================================================="
echo "[+] CONFIGURAÇÃO FINALIZADA!"
echo "[+] O serviço 'openvpn-client@aws' foi configurado e iniciado com sucesso."
echo "[+] Para monitorar os logs:  systemctl status openvpn-client@aws"
echo "[+] Para parar o serviço:    sudo systemctl stop openvpn-client@aws"
echo "=============================================================================="

