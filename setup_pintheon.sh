#!/bin/sh
echo "Installing nginx:"
apt install nginx -y
echo "Configuring Nginx"

# echo "Generate SSL Certs."
mkcert -install
mkcert local.pintheon.com localhost 127.0.0.1 ::1
mv -f local.pintheon.com+3.pem /etc/ssl/pintheon.crt
mv -f local.pintheon.com+3-key.pem /etc/ssl/pintheon.key

cat > /etc/nginx/sites-available/default << 'EOL'
# HTTP to HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name local.pintheon.com;
    return 301 https://$host$request_uri;
}

# Public server block - IPFS/IPNS and custom homepage
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name local.pintheon.com;
    client_max_body_size 200M;

    ssl_certificate /etc/ssl/pintheon.crt;
    ssl_certificate_key /etc/ssl/pintheon.key;

    # Serve custom homepage from root
    location = / {
        try_files /home/pintheon/data/custom_homepage/index.html =404;
    }

    # Serve custom homepage static files
    location /custom_homepage/ {
        alias /home/pintheon/data/custom_homepage/;
        try_files $uri $uri/ =404;
    }

    # IPFS/IPNS routes
    location ~ ^/(ipfs|ipns) {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Proxy all other requests to the application server
    location / {
        proxy_pass https://127.0.0.1:9999;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Localhost-only server block - application server
server {
    listen 127.0.0.1:9999 ssl;
    server_name local.pintheon.com;
    client_max_body_size 200M;

    ssl_certificate /etc/ssl/pintheon.crt;
    ssl_certificate_key /etc/ssl/pintheon.key;

    location / {
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' '*' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
        include proxy_params;
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }

    location ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|api_upload|api_upload_homepage|remove_file|update_logo|tokenize_file|publish_file|send_file_token|send_token|update_gateway|add_access_token|remove_access_token|dashboard_data|update_theme|update_bg_img|remove_bg_img|upload_homepage|remove_homepage|homepage_status|end_session|api/heartbeat|\.well-known/stellar\.toml) {
        include proxy_params;
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }

    location /static {
        include /etc/nginx/mime.types;
        root /home/pintheon/;
    }
}
EOL

echo "Owning the directory"
chown -R root /home/
echo "Owning the directory"
chown -R root:www-data /home/pintheon/
echo "set ownership to nginx for static files"
chmod -R 755 /home/pintheon/static

# Test NGINX configuration
echo "Testing NGINX configuration..."
nginx -t

# Restart NGINX if configuration test passes
if [ $? -eq 0 ]; then
    echo "NGINX configuration test successful, restarting NGINX..."
    systemctl restart nginx
    echo "NGINX has been restarted with the new configuration"
else
    echo "NGINX configuration test failed. Please check the configuration."
    exit 1
fi