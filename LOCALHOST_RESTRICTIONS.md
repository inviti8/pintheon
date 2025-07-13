# Localhost Route Restrictions

This document explains the localhost route restrictions feature in Pintheon, which allows you to control which routes are accessible only from localhost vs. publicly accessible routes.

## Overview

Pintheon is designed to run on localhost with some routes exposed publicly through tunnels (ngrok, pinggy, etc.). The localhost restrictions feature ensures that sensitive administrative routes are only accessible from the host machine, while public routes remain accessible through the tunnel.

## How It Works

The application uses a `@require_localhost()` decorator to restrict specific routes to localhost-only access. This decorator:

1. Checks the client's IP address (`request.remote_addr`)
2. Checks the `X-Forwarded-For` header for proxy scenarios
3. Allows access from localhost IPs: `127.0.0.1`, `::1`, `localhost`
4. Returns 403 Forbidden for non-localhost requests

## Configuration

The feature is enabled by default and can be disabled by modifying the hardcoded flag in `pintheon.py`:

```python
# Set to False for debugging if needed (rarely needed since development is on localhost)
ENABLE_LOCALHOST_RESTRICTIONS = True
```

**Note**: This flag is rarely needed since development is typically done on localhost anyway.

## Route Classification

### Localhost-Only Routes (Protected)

These routes require localhost access and are protected by the `@require_localhost()` decorator:

**Admin Interface:**
- `/admin` - Main admin dashboard
- `/top_up_stellar` - Stellar wallet top-up page

**Session Management:**
- `/end_session` - End current session
- `/reset_init` - Reset initialization
- `/new_node` - Create new node
- `/establish` - Establish node
- `/authorize` - Authorize session
- `/authorized` - Check authorization
- `/deauthorize` - Deauthorize session

**Authenticated Operations:**
- `/upload` - Upload files (authenticated)
- `/update_logo` - Update node logo
- `/update_gateway` - Update gateway URL
- `/remove_file` - Remove files from IPFS
- `/tokenize_file` - Tokenize files
- `/send_file_token` - Send file tokens
- `/send_token` - Send tokens
- `/publish_file` - Publish files
- `/add_to_namespace` - Add to IPNS namespace
- `/add_access_token` - Add API access tokens
- `/remove_access_token` - Remove API access tokens
- `/dashboard_data` - Get dashboard data
- `/update_theme` - Update theme
- `/update_bg_img` - Update background image
- `/remove_bg_img` - Remove background image
- `/upload_homepage` - Upload custom homepage
- `/remove_homepage` - Remove custom homepage
- `/homepage_status` - Get homepage status

### Public Routes (Unrestricted)

These routes remain accessible through tunnels and public networks:

**Public Content:**
- `/` - Root route (custom homepage or admin redirect)
- `/.well-known/stellar.toml` - Stellar TOML file
- `/custom_homepage/<path:filename>` - Custom homepage static files
- `/ipfs/*` and `/ipns/*` - IPFS content (handled by nginx)

**Public APIs:**
- `/api_upload` - Public file upload API (uses access tokens)
- `/api_upload_homepage` - Public homepage upload API (uses access tokens)
- `/api/heartbeat` - Health check endpoint

## Usage Examples

### Development Environment

```bash
# Run with localhost restrictions enabled (default)
python3 pintheon.py

# To disable restrictions for debugging, modify the flag in pintheon.py:
# ENABLE_LOCALHOST_RESTRICTIONS = False
```

### Container Environment

```bash
# Run container with localhost restrictions
apptainer run --bind /opt/pintheon/data:/home/pintheon/data pintheon.sif

# To disable restrictions, modify the flag in the container or source code
```

### Tunnel Setup

When using tunnels like ngrok or pinggy:

1. **Public routes** (like `/`, `/.well-known/stellar.toml`, `/api_upload`) will be accessible through the tunnel
2. **Localhost-only routes** (like `/admin`, `/upload`) will only be accessible from the host machine
3. The tunnel will receive 403 Forbidden responses for protected routes

## Security Considerations

### Benefits

- **Administrative Security**: Sensitive admin operations are restricted to localhost
- **API Security**: Public APIs use access tokens while admin APIs require localhost
- **Flexible Deployment**: Can be disabled for development or specific use cases

### Limitations

- **IP Spoofing**: The restriction relies on client IP addresses, which can be spoofed
- **Proxy Headers**: Depends on proper `X-Forwarded-For` header handling
- **Network Configuration**: May not work correctly with complex network setups

### Recommendations

1. **Use HTTPS**: Always use HTTPS in production to prevent IP spoofing
2. **Trusted Networks**: Only run on trusted networks when restrictions are disabled
3. **Access Tokens**: Use access tokens for public APIs instead of relying solely on IP restrictions
4. **Monitoring**: Monitor access logs for unauthorized attempts

## Troubleshooting

### Common Issues

**403 Forbidden on Localhost Routes:**
- Verify client IP is in localhost range
- Check `X-Forwarded-For` header in proxy scenarios
- Ensure `ENABLE_LOCALHOST_RESTRICTIONS = True` in pintheon.py

**Routes Not Restricted:**
- Verify `ENABLE_LOCALHOST_RESTRICTIONS = True` in pintheon.py
- Check that `@require_localhost()` decorator is applied to the route
- Ensure the decorator is applied before other decorators

**Tunnel Access Issues:**
- Public routes should work through tunnels
- Localhost-only routes will return 403 through tunnels
- Use access tokens for public API access

### Debug Information

The application logs debug information when access is denied:

```
DEBUG: Access denied to admin from 192.168.1.100 (X-Forwarded-For: 203.0.113.1)
```

This helps identify the source of unauthorized access attempts.

## Implementation Details

The `require_localhost()` decorator:

1. **Checks Configuration**: Skips restriction if `ENABLE_LOCALHOST_RESTRICTIONS=false`
2. **IP Validation**: Validates against localhost IP addresses
3. **Proxy Support**: Handles `X-Forwarded-For` headers for proxy scenarios
4. **Error Handling**: Returns 403 Forbidden for unauthorized access
5. **Logging**: Provides debug information for troubleshooting

The decorator is applied to routes using Flask's decorator syntax:

```python
@app.route('/admin')
@require_localhost()
def admin():
    # Route implementation
    pass
```

This ensures that the localhost check happens before other route processing. 