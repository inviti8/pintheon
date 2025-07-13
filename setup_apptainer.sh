#!/bin/sh
echo "Installing nginx:"
apt install nginx -y
echo "Configuring Nginx"

echo "Generate SSL Certs."
mkcert -install
mkcert local.pintheon.com localhost 127.0.0.1 ::1
mv -f local.pintheon.com+3.pem /etc/ssl/pintheon.crt
mv -f local.pintheon.com+3-key.pem /etc/ssl/pintheon.key

cat > /etc/nginx/sites-available/default<<  EOF

server{
    listen 80;
    server_name local.pintheon.com;
    client_max_body_size 200M;

    location / {
        return 301 https://\$host\$request_uri;
     }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name local.pintheon.com;
    client_max_body_size 200M;

    ssl_certificate /etc/ssl/pintheon.crt;
    ssl_certificate_key /etc/ssl/pintheon.key;

    location ~ ^/(ipfs|ipns) {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
	}

    # Custom homepage static files
    location /custom_homepage/ {
        alias /home/pintheon/data/custom_homepage/;
        try_files \$uri \$uri/ =404;
    }

    # Protected routes - localhost only
    location ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|api_upload|api_upload_homepage|remove_file|update_logo|tokenize_file|publish_file|send_file_token|send_token|update_gateway|add_access_token|remove_access_token|dashboard_data|update_theme|update_bg_img|remove_bg_img|upload_homepage|remove_homepage|homepage_status|end_session|api/heartbeat) {
        # IP filtering - allow localhost and private network ranges
        allow 127.0.0.1;
        allow ::1;
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
        
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods *;

        include proxy_params;
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }

    # Public routes - any IP (including Stellar TOML)
    location ~ ^/(\.well-known/stellar\.toml) {
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods *;

        include proxy_params;
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }

    # Root location - serve custom homepage or redirect to admin
    location / {
        include proxy_params;
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }

    location /static  {
        include  /etc/nginx/mime.types;
        root /home/pintheon/;
    }
}
EOF

echo "Owning the directory"
chown -R root /home/
echo "Owning the directory"
chown -R root:www-data /home/pintheon/
echo "set ownership to nginx for staic files"
chmod -R 755 /home/pintheon/static

