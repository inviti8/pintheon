#!/bin/sh
echo "Creating gunicorn service"
cat > /etc/systemd/system/gunicorn.service <<  EOF
[Unit]
Description=Gunicorn Service
After=network.target

[Service]
User=test
Group=www-data
WorkingDirectory=/home/test/pintheon
Environment="PATH=/home/test/pintheon/bin"
ExecStart=/home/test/pintheon/pintheon/bin/gunicorn --workers 1 --limit-request-line 0 --bind unix:pintheon.sock -m 007 wsgi:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Starting Gunicorn Service..."
sudo systemctl daemon-reload
sudo systemctl enable gunicorn.service
sudo systemctl start gunicorn.service


echo "Installing nginx:"
sudo apt install nginx -y
echo "Configuring Nginx"

echo "Generate SSL Certs."
mkcert -install
mkcert local.pintheon.com localhost 127.0.0.1 ::1
sudo mv -f local.pintheon.com+3.pem /etc/ssl/pintheon.crt
sudo mv -f local.pintheon.com+3-key.pem /etc/ssl/pintheon.key
#openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/localhost.key -out certs/localhost.crt -config ./pintheon/localhost.cnf -extensions ext
#sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/localhost.key -out /etc/ssl/certs/localhost.crt -config ./pintheon/localhost.cnf

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

    location ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|api_upload|remove_file|update_logo|tokenize_file|publish_file|send_file_token|send_token|update_gateway|add_access_token|remove_access_token|dashboard_data|update_theme|update_bg_img|remove_bg_img|end_session) {
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods *;

        include proxy_params;
        proxy_pass http://unix:/home/test/pintheon/pintheon.sock;
    }

    location /static  {
        include  /etc/nginx/mime.types;
        root /home/test/pintheon/;
    }
}
EOF

echo "Owning the directory"
sudo chown -R test /home/
echo "Owning the directory"
sudo chown -R test:www-data /home/test/pintheon/
echo "set ownership to nginx for staic files"
sudo chmod -R 755 /home/test/pintheon/static
echo "Restarting Nginx"
sudo systemctl restart nginx