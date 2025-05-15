#!/bin/sh
# echo "Creating gunicorn service"
# cat > /etc/systemd/system/gunicorn.service <<  EOF
# [Unit]
# Description=Gunicorn Service
# After=network.target

# [Service]
# User=test
# Group=www-data
# WorkingDirectory=/philos
# Environment="PATH=/philos/bin"
# ExecStart=/philos/philos/bin/gunicorn --workers 1 --limit-request-line 0 --bind unix:philos.sock -m 007 wsgi:app
# Restart=always

# [Install]
# WantedBy=multi-user.target
# EOF

# echo "Starting Gunicorn Service..."
# # systemctl daemon-reload
# # systemctl enable gunicorn.service
# chkconfig gunicorn on
# # systemctl start gunicorn.service
# service gunicorn start


echo "Installing nginx:"
apt install nginx -y
echo "Configuring Nginx"

echo "Generate SSL Certs."
mkcert -install
mkcert local.philos.com localhost 127.0.0.1 ::1
mv -f local.philos.com+3.pem /etc/ssl/philos.crt
mv -f local.philos.com+3-key.pem /etc/ssl/philos.key
#openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout certs/localhost.key -out certs/localhost.crt -config ./philos/localhost.cnf -extensions ext
#sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/localhost.key -out /etc/ssl/certs/localhost.crt -config ./philos/localhost.cnf

cat > /etc/nginx/sites-available/default<<  EOF

server{
    listen 80;
    server_name local.philos.com;
    client_max_body_size 200M;

    location / {
        return 301 https://\$host\$request_uri;
     }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name local.philos.com;
    client_max_body_size 200M;

    ssl_certificate /etc/ssl/philos.crt;
    ssl_certificate_key /etc/ssl/philos.key;

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
chown -R root /home/
echo "Owning the directory"
chown -R root:www-data /home/philos/
echo "set ownership to nginx for staic files"
chmod -R 755 /home/philos/static
echo "Restarting Nginx"
# systemctl restart nginx
service nginx restart