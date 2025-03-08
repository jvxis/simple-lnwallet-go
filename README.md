# ⚡ Lightning Wallet CLI

Este é um **serviço web minimalista de carteira Lightning Network** que se conecta a um node LND via gRPC.  
Ele permite visualizar informações do node, criar faturas e pagar invoices.
![image](https://github.com/user-attachments/assets/cd4e5090-eb3a-455a-b9b5-a4b897313733)
![image](https://github.com/user-attachments/assets/db97c717-b624-4ea8-9ecd-666feeb0b7f6)

🚀 **Tecnologias usadas**:
- Golang
- gRPC (para comunicação com LND)
- BoldB (armazenamento de nodes)
- QR Code para pagamento

---

## 📌 **1. Requisitos**
Antes de começar, certifique-se de ter:
- **Acesso ao seu LND via gRPC** (porta `10009`). Recomendamos o uso de uma VPN como o Tailscale para esse fim. Dessa maneira não é necessário abrir portas.
- **Se você for executar o app em uma máquina diferente da de onde esta o node, precisa ter no seu `lnd.conf` o comando `rpclisten=0.0.0.0:10009`.
- **Admin Macaroon e TLS Cert em formato HEX**.

Se estiver no **Raspberry Pi 4**, instale `xxd` para extrair os arquivos:
```bash
sudo apt update && sudo apt install xxd -y
```
## **2. Instalando o Binário**
Basta fazer o download do Binário

*Windows: final .exe*
Clicar no link para Download
https://github.com/jvxis/simple-lnwallet-go/releases/download/v.0.0.1/simple-lnwallet.exe

*Linux*
```bash
wget https://github.com/jvxis/simple-lnwallet-go/releases/download/v.0.0.1/simple-lnwallet
chmod +x simple-lnwallet
```

*MacOs*
Clicar no link para download
https://github.com/jvxis/simple-lnwallet-go/releases/download/v.0.0.1/simple-lnwallet-mac.exe

## **3. Extraindo as Credenciais do LND**
Executar no diretório `/home/admin`
```bash
xxd -p ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon | tr -d '\n' > macaroon.hex
xxd -p ~/.lnd/tls.cert | tr -d '\n' > tls.hex
```
## **4. Executando a Aplicação**
Utilize uma VPN ou Tailscale por questão de segurança
Na máquina host execute:
###Linux
```bash
./simple-lnwallet
```
###Windows
Abrir o linha de comando CMD
```bash
simple-lnwallet
```
###MacOs
```bash
./simple-lnwallet-mac
```

**Você acessa a app com `http://nome-maquina:35671`**

**Recomendamos o uso via VPN ou Tailscale. Assim na tela de conexão pode usar o `nome-da-maquina:10009` ou `ip-vpn:10009` ou `ip-tailscale:10009`**

## **Importante**
**Para habitar a leitura de QRCODE via dispositivos móveis, precisa fazer o acesso com https.**

**Para tal você precisa instalar certificados self-sign na máquina host e criar um proxy reverso - Instruções abaixo**

https://github.com/jvxis/simple-lnwallet-go/blob/main/self-certificate.md

**Fazendo esse procedimento, você poderá acessar com `https://nome-maquina` somente.**
