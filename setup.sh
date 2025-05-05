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
        include proxy_params;
        proxy_pass http://unix:/home/test/philos/philos.sock;
    }

}
EOF

echo "Restarting Nginx"
sudo systemctl restart nginx

echo "Owning the directory"
sudo chown -R test /home/
echo "Owning the directory"
sudo chown -R test:www-data /home/test/philos/