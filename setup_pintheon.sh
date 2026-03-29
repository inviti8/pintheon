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
# SSL configuration
ssl_certificate /etc/ssl/pintheon.crt;
ssl_certificate_key /etc/ssl/pintheon.key;

# HTTP server - redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name local.pintheon.com localhost 127.0.0.1;
    return 301 https://$host$request_uri;
}

# Public HTTPS server (port 9998)
server {
    listen 9998 ssl;
    listen [::]:9998 ssl;
    server_name local.pintheon.com localhost 127.0.0.1;
    client_max_body_size 50M;
    
    # SSL configuration
    ssl_certificate /etc/ssl/pintheon.crt;
    ssl_certificate_key /etc/ssl/pintheon.key;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'self'; form-action 'self'; base-uri 'self';";
    
    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
    
    # Increase timeouts
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;
    
    # Proxy settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Handle root-level static files from custom homepage
    location = /robots.txt {
        root /home/pintheon/data/custom_homepage;
        try_files $uri =404;
        access_log off;
        log_not_found off;
        expires 1d;
    }

    location = /sitemap.xml {
        root /home/pintheon/data/custom_homepage;
        try_files $uri =404;
        access_log off;
        log_not_found off;
        expires 1h;
    }

    # Handle favicon and other root assets
    location = /favicon.ico {
        root /home/pintheon/data/custom_homepage;
        try_files $uri =404;
        access_log off;
        log_not_found off;
        expires 1w;
    }

    # Handle open graph image
    location = /og-image.jpg {
        root /home/pintheon/data/custom_homepage;
        try_files $uri =404;
        access_log off;
        log_not_found off;
        expires 1w;
    }
    
    # Serve custom homepage with VitePress routing support
    location / {
        root /home/pintheon/data/custom_homepage;
        # Try exact match, then .html extension, then directory, then 404
        try_files $uri $uri.html $uri/ =404;
        
        # Handle 404 errors with custom page
        error_page 404 /404.html;
        
        # Handle directory access without index.html
        error_page 403 /404.html;
        
        # Cache static assets
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, max-age=31536000, immutable";
        }
    }
    
    # Serve custom homepage static files
    location /home/ {
        alias /home/pintheon/data/custom_homepage/;
        try_files $uri $uri/ =404;
        expires 30d;
        access_log off;
    }
    
    # IPFS/IPNS routes
    location ~ ^/(ipfs|ipns) {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # Serve static files directly
    location /static/ {
        alias /home/pintheon/static/;
        expires 30d;
        access_log off;
    }
    
    # Application routes
    location @app {
        # Deny access to admin routes
        if ($uri ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|api_upload|api_upload_homepage|api_create_directory|api_list_directories|api_get_directory_ipns|api_list_ipns_keys|api_publish_directory|api/upload_folder|api/pinned_files|remove_file|update_logo|tokenize_file|publish_file|send_file_token|send_token|update_gateway|add_access_token|remove_access_token|dashboard_data|update_theme|update_bg_img|remove_bg_img|upload_homepage|remove_homepage|homepage_status|update_homepage_type|update_stellar_toml|top_up_stellar|update_homepage_hash|hash_is_html|end_session|api/heartbeat|\.well-known/stellar\.toml)) {
            return 403;
        }
        
        # Proxy all other requests to Gunicorn
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }
}

# Private HTTPS server (port 9999, protected by IP restrictions)
server {
    listen 9999 ssl;
    listen [::]:9999 ssl;
    server_name local.pintheon.com localhost 127.0.0.1;
    client_max_body_size 200M;
    
    # SSL configuration
    ssl_certificate /etc/ssl/pintheon.crt;
    ssl_certificate_key /etc/ssl/pintheon.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' data: https:; connect-src 'self' https: wss:; frame-ancestors 'self'; form-action 'self'; base-uri 'self';";
    
    # Logging
    access_log /var/log/nginx/access_private.log;
    error_log /var/log/nginx/error_private.log;
    
    # Increase timeouts
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;
    
    # Proxy settings
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    
    # Serve static files directly
    location /static/ {
        alias /home/pintheon/static/;
        expires 30d;
        access_log off;
    }
    
    # Admin and API routes (only accessible on private port 9999)
    location ~ ^/(admin|reset_init|new_node|establish|authorize|authorized|deauthorize|upload|api_upload|api_upload_homepage|api_create_directory|api_list_directories|api_get_directory_ipns|api_list_ipns_keys|api_publish_directory|api/upload_folder|api/pinned_files|remove_file|update_logo|tokenize_file|publish_file|send_file_token|send_token|update_gateway|add_access_token|remove_access_token|dashboard_data|update_theme|update_bg_img|remove_bg_img|upload_homepage|remove_homepage|homepage_status|update_homepage_type|update_stellar_toml|top_up_stellar|update_homepage_hash|hash_is_html|end_session|api/heartbeat|\.well-known/stellar\.toml) {
        # Allow all IPs for now to test
        allow all;
        
        # Proxy settings
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeouts
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
        
        proxy_pass http://unix:/home/pintheon/pintheon.sock;
    }
    
    # Default route for private server
    location / {
        # Allow access to root but redirect to admin if accessed directly
        if ($request_uri = /) {
            return 301 /admin;
        }
        
        # For any other non-admin route, deny access
        return 403;
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