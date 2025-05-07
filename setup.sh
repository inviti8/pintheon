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
ExecStart=/home/test/philos/philos/bin/gunicorn --workers 3 --bind unix:philos.sock -m 007 wsgi:app
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

    location / {
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
sudo chown -R nginx:nginx /home/test/philos/static
sudo chmod -R 755 /home/test/philos/static
echo "Restarting Nginx"
sudo systemctl restart nginx