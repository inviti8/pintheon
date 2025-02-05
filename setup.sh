#!/bin/sh
echo "Creating gunicorn service"
cat > /etc/systemd/system/gunicorn.service <<  EOF
[Unit]
Description=Gunicorn Service
After=network.target

[Service]
User=test
Group=www-data
WorkingDirectory=/home/test/axiel
Environment="PATH=/home/test/axiel/bin"
ExecStart=/home/test/axiel/axiel/bin/gunicorn --workers 3 --bind unix:axiel.sock -m 007 wsgi:app
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
        proxy_pass http://unix:/home/test/axiel/axiel.sock;
    }
}
EOF

echo "Restarting Nginx"
sudo systemctl restart nginx