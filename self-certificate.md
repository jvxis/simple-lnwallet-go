# Instruções para Gerar Certificado Autoassinado e Configurar Nginx

## 1. Gerar o Certificado Autoassinado com OpenSSL

### Passo 1: Criar a chave privada
Abra o terminal na sua máquina Linux e execute:
```bash
openssl genrsa -out selfsigned.key 2048
```
Isso gera uma chave privada de 2048 bits chamada **selfsigned.key**.

### Passo 2: Gerar um certificado autoassinado
Execute o comando abaixo para criar o certificado. Você pode ajustar os campos conforme necessário. O comando abaixo gera um certificado válido por 365 dias:
```bash
openssl req -new -x509 -key selfsigned.key -out selfsigned.crt -days 365
```
Durante esse comando, você será solicitado a inserir informações como país, estado, cidade, nome da organização e o **Common Name**. No campo **Common Name** informe o nome do host que você utilizará (pode ser o nome interno ou o endereço que você usa na VPN).

---

## 2. Configurar o Nginx para Usar o Certificado Autoassinado

### Passo 3: Instalar o Nginx (se já não estiver instalado)
Em distribuições Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nginx
```

### Passo 4: Copiar os certificados para um diretório adequado
Por exemplo, crie um diretório para os certificados:
```bash
sudo mkdir -p /etc/nginx/ssl
sudo cp selfsigned.crt /etc/nginx/ssl/
sudo cp selfsigned.key /etc/nginx/ssl/
```

### Passo 5: Configurar o arquivo do site no Nginx
Crie um arquivo de configuração para o seu proxy reverso. Por exemplo, crie o arquivo `/etc/nginx/sites-available/meuproxy` com o conteúdo:
```nginx
server {
    listen 443 ssl;
    server_name SEU_NOME_HOST;  # substitua pelo nome que você usará na VPN

    ssl_certificate /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://127.0.0.1:35671;  # endereço da sua aplicação Go
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### Dica: Redirecionando HTTP para HTTPS
Se desejar, você pode criar um bloco `server` para redirecionar o HTTP para HTTPS:
```nginx
server {
    listen 80;
    server_name SEU_NOME_HOST;
    return 301 https://$host$request_uri;
}
```

### Passo 6: Habilitar a configuração no Nginx
Crie um link simbólico para ativar o site:
```bash
sudo ln -s /etc/nginx/sites-available/meuproxy /etc/nginx/sites-enabled/
```

### Passo 7: Testar e Reiniciar o Nginx
Teste a configuração do Nginx:
```bash
sudo nginx -t
```
Se não houver erros, reinicie o Nginx:
```bash
sudo systemctl restart nginx
```
