#!/bin/sh
echo "Creating gunicorn service"
cat > /etc/systemd/system/gunicorn.service <<  EOF
[Unit]
Description=Gunicorn Service
After=network.target

[Service]
User=test
Group=www-data
WorkingDirectory=/home/test/philos
Environment="PATH=/home/test/philos/bin"
ExecStart=/home/test/philos/philos/bin/gunicorn --workers 1 --limit-request-line 0 --bind unix:philos.sock -m 007 wsgi:app
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
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/localhost.key -out certs/localhost.crt -config ./localhost.cnf -extensions ext

cat > /etc/nginx/sites-available/default<<  EOF

server{
    listen 80;
    server_name localhost;
    client_max_body_size 200M;

    location / {
        return 301 https://$host$request_uri;
     }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name localhost;
    client_max_body_size 200M;

    http2 on;

    ssl_certificate /etc/ssl/localhost.crt;
    ssl_certificate_key /etc/ssl/localhost.key;
    
    ssl_protocols TLSv1.2 TLSv1.1 TLSv1;

    location ~ ^/(ipfs|ipns) {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
	}

    location ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|upload_logo|end_session) {
        add_header Access-Control-Allow-Origin *;
        add_header Access-Control-Allow-Methods *;

        include proxy_params;
        proxy_pass http://unix:/home/test/philos/philos.sock;
    }

    location /static  {
        include  /etc/nginx/mime.types;
        root /home/test/philos/;
    }
}
EOF

echo "Owning the directory"
sudo chown -R test /home/
echo "Owning the directory"
sudo chown -R test:www-data /home/test/philos/
echo "set ownership to nginx for staic files"
sudo chmod -R 755 /home/test/philos/static
echo "Restarting Nginx"
sudo systemctl restart nginx