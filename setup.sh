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
        add_header Access-Control-Allow-Origin $allow_origin;
        add_header Access-Control-Allow-Methods $allow_methods;

        # Handling preflight requests
        if ($request_method = OPTIONS) {
            add_header Access-Control-Allow-Origin $allow_origin;
            add_header Access-Control-Allow-Methods $allow_methods;
            add_header Content-Type text/plain;
            add_header Content-Length 0;
            return 204;
        }
        
        include proxy_params;
        proxy_pass http://unix:/home/test/philos/philos.sock;
    }

    location /static  {
        include  /etc/nginx/mime.types;
        root /home/test/philos/;
    }
}
EOF

echo "Restarting Nginx"
sudo systemctl restart nginx

echo "Owning the directory"
sudo chown -R test /home/
echo "Owning the directory"
sudo chown -R test:www-data /home/test/philos/