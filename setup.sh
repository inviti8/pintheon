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
ExecStart=/home/test/philos/philos/bin/gunicorn --workers 1 --bind unix:philos.sock -m 007 wsgi:app
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

cat > /etc/nginx/sites-available/default<<  EOF
server{
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host `echo $host`;
        proxy_set_header X-Real-IP `echo $remote_addr`;
        proxy_set_header X-Forwarded-For `echo $proxy_add_x_forwarded_for`;
        proxy_set_header X-Forwarded-Proto `echo $scheme`;
	}

    location /admin {
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