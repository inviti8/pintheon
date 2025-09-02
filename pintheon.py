import os
import requests
import zipfile
import tempfile
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for, send_file, make_response, send_from_directory
from flask_cors import CORS, cross_origin
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, HTTPException
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query
from platformdirs import *
from pintheonMachine import PintheonMachine
from StellarTomlGenerator import StellarTomlGenerator
from pymacaroons import Macaroon, Verifier, MACAROON_V1, MACAROON_V2
from functools import wraps
import mimetypes
import shutil

app = Flask(__name__)
app.secret_key = os.urandom(24)
MEGABYTE = (2 ** 10) ** 2
app.config['MAX_CONTENT_LENGTH'] = None
app.config['MAX_FORM_MEMORY_SIZE'] = 200 * MEGABYTE



CORS(app)

SCRIPT_DIR = os.path.abspath( os.path.dirname( __file__ ) )
# LOCAL_DEBUG = True

# Use platformdirs for cross-platform data directory management
def get_data_directory():
    """Get the appropriate data directory using platformdirs with fallback"""
    # Try environment variable first
    env_data_dir = os.environ.get('PINTHEON_DATA_DIR')
    if env_data_dir:
        return env_data_dir
    
    # Use platformdirs for default location (no app author)
    dirs = PlatformDirs('PINTHEON', ensure_exists=True)
    
    # For container environments, prefer /home/pintheon/data
    # For development, use platformdirs user_data_dir directly
    if os.path.exists('/.dockerenv') or os.environ.get('APPTAINER_CONTAINER'):
        # Container environment
        default_container_path = '/home/pintheon/data'
        try:
            os.makedirs(default_container_path, exist_ok=True)
            return default_container_path
        except (OSError, PermissionError):
            # Fallback to platformdirs if container path not writable
            return dirs.user_data_dir
    else:
        # Development environment - use platformdirs directly
        return dirs.user_data_dir

# Get data directory with fallback
PINTHEON_DATA_DIR = get_data_directory()
PINTHEON_IPFS_PATH = os.environ.get('PINTHEON_IPFS_PATH', os.path.join(PINTHEON_DATA_DIR, 'ipfs'))
PINTHEON_DB_PATH = os.environ.get('PINTHEON_DB_PATH', os.path.join(PINTHEON_DATA_DIR, 'db'))

# Updated paths using environment variables
STATIC_PATH = os.path.join(SCRIPT_DIR, "static")
DB_PATH = os.path.join(PINTHEON_DB_PATH, "enc_db.json")
COMPONENT_PATH = os.path.join(SCRIPT_DIR, "components")

# Ensure data directories exist with error handling
def ensure_directories():
    """Create data directories if they don't exist"""
    global PINTHEON_DATA_DIR, PINTHEON_IPFS_PATH, PINTHEON_DB_PATH, CUSTOM_HOMEPAGE_PATH
    
    # Define CUSTOM_HOMEPAGE_PATH here after PINTHEON_DATA_DIR is set
    CUSTOM_HOMEPAGE_PATH = os.path.join(PINTHEON_DATA_DIR, "custom_homepage")
    
    directories = [PINTHEON_DATA_DIR, PINTHEON_DB_PATH, PINTHEON_IPFS_PATH, CUSTOM_HOMEPAGE_PATH]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except (OSError, PermissionError) as e:
            print(f"Warning: Could not create directory {directory}: {e}")
            # If we can't create the main data dir, try a fallback
            if directory == PINTHEON_DATA_DIR:
                fallback_dir = os.path.join(os.path.expanduser("~"), "pintheon_data")
                try:
                    os.makedirs(fallback_dir, exist_ok=True)
                    print(f"Using fallback directory: {fallback_dir}")
                    # Update all paths to use fallback
                    PINTHEON_DATA_DIR = fallback_dir
                    PINTHEON_IPFS_PATH = os.path.join(fallback_dir, 'ipfs')
                    PINTHEON_DB_PATH = os.path.join(fallback_dir, 'db')
                    CUSTOM_HOMEPAGE_PATH = os.path.join(fallback_dir, 'custom_homepage')
                    # Create the subdirectories
                    os.makedirs(PINTHEON_IPFS_PATH, exist_ok=True)
                    os.makedirs(PINTHEON_DB_PATH, exist_ok=True)
                    os.makedirs(CUSTOM_HOMEPAGE_PATH, exist_ok=True)
                    break
                except (OSError, PermissionError) as e2:
                    print(f"Error: Could not create fallback directory {fallback_dir}: {e2}")
                    raise

ensure_directories()

# Now define CUSTOM_HOMEPAGE_PATH globally after ensure_directories() has run
CUSTOM_HOMEPAGE_PATH = os.path.join(PINTHEON_DATA_DIR, "custom_homepage")

PINTHEON = PintheonMachine(static_path=STATIC_PATH, db_path=DB_PATH, toml_gen=StellarTomlGenerator, testnet=True, debug=False, fake_ipfs=False)
if PINTHEON.state == None or PINTHEON.state == 'spawned':
     PINTHEON.initialize()

##UTILITIES###

def _load_components(comp):
   result = None
   with open(os.path.join(COMPONENT_PATH, f'{comp}.html'), 'r') as f:
        result = f.read()

   return result

def _load_js(comp):
 return url_for('static', filename=f'{comp}.js')

def _payload_valid(fields, data):
   result = True
   for field in fields:
      if field not in data:
         result = False
         break

   return result

def require_fields(fields, source='json'):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            print(f"DEBUG: require_fields decorator called for {f.__name__}")
            print(f"DEBUG: fields: {fields}, source: {source}")
            if source == 'json':
                data = request.get_json()
                print(f"DEBUG: JSON data keys: {list(data.keys()) if data else 'None'}")
                if not _payload_valid(fields, data):
                    print(f"DEBUG: Missing fields in JSON data")
                    abort(400)
                return f(*args, **kwargs)
            elif source == 'form':
                print(f"DEBUG: Form data keys: {list(request.form.keys())}")
                for field in fields:
                    if field not in request.form:
                        print(f"DEBUG: Missing field in form: {field}")
                        return "Missing or empty value for field: {}".format(field), 400
                return f(*args, **kwargs)
            else:
                print(f"DEBUG: Invalid source: {source}")
                abort(400)
        return wrapper
    return decorator

def require_session_state(state='idle', active=True):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            print(f"DEBUG: require_session_state decorator called for {f.__name__}")
            print(f"DEBUG: required state: {state}, current state: {PINTHEON.state}")
            print(f"DEBUG: active required: {active}, session_active: {PINTHEON.session_active}")
            if active and not PINTHEON.session_active:
                print(f"DEBUG: Session not active")
                abort(403)
            if state and not PINTHEON.state == state:
                print(f"DEBUG: State mismatch - required: {state}, current: {PINTHEON.state}")
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def require_token_verification(pub_field, token_field, source='json'):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            print(f"DEBUG: require_token_verification decorator called for {f.__name__}")
            print(f"DEBUG: pub_field: {pub_field}, token_field: {token_field}, source: {source}")
            if source == 'json':
                data = request.get_json()
                print(f"DEBUG: JSON data for verification: {data}")
                if not PINTHEON.verify_request(data[pub_field], data[token_field]):
                    print(f"DEBUG: Token verification failed for JSON")
                    raise Unauthorized()
            elif source == 'form':
                print(f"DEBUG: Form data for verification: pub={request.form.get(pub_field)}, token={request.form.get(token_field)}")
                if not PINTHEON.verify_request(request.form[pub_field], request.form[token_field]):
                    print(f"DEBUG: Token verification failed for form")
                    raise Unauthorized()
            else:
                print(f"DEBUG: Invalid source for token verification: {source}")
                abort(400)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def require_local_access(f):
    """Decorator to restrict access to local requests only (not custom domain)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        host = request.headers.get('Host', '')
        forwarded_host = request.headers.get('X-Forwarded-Host', '')
        
        # Get the current custom hostname from Pintheon
        custom_host = PINTHEON.url_host if PINTHEON.url_host else None
        port = str(PINTHEON.port)
        # if LOCAL_DEBUG:
        #     port = '5000'
        
        # If no custom hostname is set (still localhost), allow access
        if not custom_host or custom_host in ['localhost', '127.0.0.1', f'localhost:{port}', f'127.0.0.1:{port}']:
            print(f"DEBUG: Allowed local access to {f.__name__} - no custom domain set")
            return f(*args, **kwargs)
        
        # Extract hostname from custom_host (remove protocol if present)
        if custom_host.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(custom_host)
            custom_hostname = parsed.netloc
        else:
            custom_hostname = custom_host
        
        # Check if request is coming through the custom domain
        request_hosts = [host, forwarded_host]
        for request_host in request_hosts:
            if request_host and custom_hostname in request_host:
                print(f"DEBUG: Blocked external access to {f.__name__} from {request_host} (custom domain: {custom_hostname})")
                raise Forbidden()
        
        print(f"DEBUG: Allowed local access to {f.__name__} from Host: {host}, X-Forwarded-Host: {forwarded_host}")
        return f(*args, **kwargs)
    return decorated_function

def _handle_upload(required, request, is_logo=False, is_bg_img=False, encrypted=False, return_file_info=False):
    if 'file' not in request.files:
        return "No file uploaded", 400
     
    file = request.files['file']
    print(file)
    print(file.filename)
    print(file.mimetype)

     
    for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

    file_data = file.read()
    file_name = file.filename
    file_type = file.mimetype
    reciever_pub = None

    if encrypted == 'true':
        reciever_pub = request.form['reciever_pub']
        file_data = PINTHEON.stellar_shared_archive(file, reciever_pub)
        file_name = f"{file.filename}.7z"
        file_type = 'application/x-7z-compressed'

    ipfs_response = PINTHEON.add_file_to_ipfs(file_name=file_name, file_type=file_type, file_data=file_data, is_logo=is_logo, is_bg_img=is_bg_img, encrypted=encrypted, reciever_pub=reciever_pub, return_file_info=return_file_info)

    print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
    print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
    print(ipfs_response)
    print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')
    print('%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%')

    if ipfs_response == None:
        return jsonify({'error': 'File not added'}), 400
    else:
        return ipfs_response
    
def _get_file_cid(file, files):
    cid = None
    if files != None:
        file_list = files
        for dat in file_list:
            if dat['Name'] == file.filename and dat['Type'] == file.mimetype:
                cid = dat['CID']
                break

    return cid

def _get_mime_type(filename):
    """Get MIME type for a file"""
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'

def _ensure_protocol(url, default_protocol='https'):
    """Ensure URL has the correct protocol. If no protocol is present, add the default."""
    if url and not url.startswith(('http://', 'https://')):
        return f"{default_protocol}://{url}"
    return url

def _custom_homepage_exists():
    """Check if a custom homepage exists"""
    index_files = ['index.html', 'index.htm', 'index.php']
    
    # Check in root directory first
    for filename in index_files:
        if os.path.exists(os.path.join(CUSTOM_HOMEPAGE_PATH, filename)):
            return True
    
    # Check in subdirectories
    for root, dirs, files in os.walk(CUSTOM_HOMEPAGE_PATH):
        for filename in files:
            if filename in index_files:
                return True
    
    return False

def _get_custom_homepage_file():
    """Get the main file of the custom homepage"""
    index_files = ['index.html', 'index.htm', 'index.php']
    
    # Check in root directory first
    for filename in index_files:
        filepath = os.path.join(CUSTOM_HOMEPAGE_PATH, filename)
        if os.path.exists(filepath):
            return filename
    
    # Check in subdirectories
    for root, dirs, files in os.walk(CUSTOM_HOMEPAGE_PATH):
        for filename in files:
            if filename in index_files:
                # Return the relative path from CUSTOM_HOMEPAGE_PATH
                rel_path = os.path.relpath(os.path.join(root, filename), CUSTOM_HOMEPAGE_PATH)
                return rel_path
    
    return None

def _extract_zip_to_homepage(zip_file):
    """Extract uploaded ZIP file to custom homepage directory"""
    try:
        # Clear existing homepage
        if os.path.exists(CUSTOM_HOMEPAGE_PATH):
            shutil.rmtree(CUSTOM_HOMEPAGE_PATH)
        os.makedirs(CUSTOM_HOMEPAGE_PATH, exist_ok=True)
        
        # Extract ZIP file
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(CUSTOM_HOMEPAGE_PATH)
        
        # Debug: List extracted files
        print(f"DEBUG: Extracted files in {CUSTOM_HOMEPAGE_PATH}:")
        for root, dirs, files in os.walk(CUSTOM_HOMEPAGE_PATH):
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), CUSTOM_HOMEPAGE_PATH)
                print(f"DEBUG:   {rel_path}")
        
        return True
    except Exception as e:
        print(f"Error extracting ZIP file: {e}")
        return False
        


##ERROR HANDLING##
class Forbidden(HTTPException):
    code = 403
    description = 'You do not have the permission to perform this action'

class Unauthorized(HTTPException):
    code = 401
    description = 'Invalid Credentials'

def _on_failure_error():
    pass  # Removed global session end

@app.errorhandler(401)
def unauthorized_access(e):
    # _on_failure_error()  # No longer ends session
    return 'Access Denied', 401

@app.errorhandler(Forbidden)
def handle_forbidden(e):
    # _on_failure_error()  # No longer ends session
    return 'Permission Denied', 403

@app.errorhandler(500)
def unauthorized_access(e):
    # _on_failure_error()  # No longer ends session
    return 'Server Error', 500

##ROUTES## 

@app.route('/')
def root():
    """Root route - serve custom homepage if exists, otherwise return 403"""
    if PINTHEON.homepage_type == 'upload' and _custom_homepage_exists():
        index_file = _get_custom_homepage_file()
        # If the index file is in a subdirectory, we need to handle it properly
        if '/' in index_file:
            # Index file is in a subdirectory, serve it from the subdirectory
            subdir = os.path.dirname(index_file)
            filename = os.path.basename(index_file)
            return send_from_directory(os.path.join(CUSTOM_HOMEPAGE_PATH, subdir), filename)
        else:
            # Index file is in the root directory
            return send_from_directory(CUSTOM_HOMEPAGE_PATH, index_file)
    elif PINTHEON.homepage_hash != 'none' and PINTHEON.homepage_type == 'ipfs-hash' and PINTHEON.file_hash_exists(PINTHEON.homepage_hash, 'text/html'):
        home = _ensure_protocol(PINTHEON.url_host)+'/ipfs/'+PINTHEON.homepage_hash
        return redirect(home)
    else:
        abort(403)

@app.route('/custom_homepage/<path:filename>')
def custom_homepage_static(filename):
    """Serve static files from custom homepage directory"""
    return send_from_directory(CUSTOM_HOMEPAGE_PATH, filename)

@app.route('/admin')
def admin():
    # Access check FIRST
    host = request.headers.get('Host', '')
    forwarded_host = request.headers.get('X-Forwarded-Host', '')
    custom_host = PINTHEON.url_host if PINTHEON.url_host else None
    port = str(PINTHEON.port)
    # if LOCAL_DEBUG:
    #         port = '5000'
    if custom_host and custom_host not in ['localhost', '127.0.0.1', f'localhost:{port}', f'127.0.0.1:{port}']:
        # Extract hostname from custom_host (remove protocol if present)
        if custom_host.startswith(('http://', 'https://')):
            from urllib.parse import urlparse
            parsed = urlparse(custom_host)
            custom_hostname = parsed.netloc
        else:
            custom_hostname = custom_host
        if (host and custom_hostname in host) or (forwarded_host and custom_hostname in forwarded_host):
            print(f"DEBUG: Blocked external access to admin from {host} / {forwarded_host} (custom domain: {custom_hostname})")
            raise Forbidden()
    print('-----------------------------------')
    print(PINTHEON.state)
    print(request.headers)
    print(PINTHEON.soroban_online())
    print('-----------------------------------')

    PINTHEON.logo_url = url_for('static', filename='pintheon_logo.png')
    PINTHEON.stellar_logo_url = url_for('static', filename='stellar_logo.png')
    stellar_light_logo = url_for('static', filename='stellar_logo_light.png')
    stellar_dark_logo = url_for('static', filename='stellar_logo_dark.png')

    if PINTHEON.stellar_logo == None:
      PINTHEON.stellar_set_logos(stellar_light_logo, stellar_dark_logo)
    PINTHEON.stellar_wallet_qr = url_for('static', filename='stellar_wallet_qr.png')
    PINTHEON.opus_logo = url_for('static', filename='opus.png')
    PINTHEON.boros_logo = url_for('static', filename='boros.png')

    pub = PINTHEON.session_pub
    if not PINTHEON.logged_in:
        pub = PINTHEON.new_session()

    template = PINTHEON.view_template
    components=_load_components(PINTHEON.view_components)
    page = PINTHEON.active_page
    js=_load_js(PINTHEON.view_components)
    logo=PINTHEON.logo_url
    customization = PINTHEON.get_customization()
    theme = customization['themes'][customization['current_theme']]
    bg_img = customization['bg_img']
    shared_dialogs=_load_components(PINTHEON.shared_dialogs)
    shared_dialogs_js=_load_js(PINTHEON.shared_dialogs)
    client_tokens= _load_js('macaroons_js_bundle')
    theme_css = url_for('static', filename=theme+'-theme.css')
    
    session_data = { 'pub': pub, 'generator_pub': PINTHEON.node_pub, 'time': PINTHEON.session_ends, 'nonce': PINTHEON.session_nonce }
    return render_template(template, page=page, components=components, js=js, logo=logo, bg_img=bg_img, theme_css=theme_css, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js, client_tokens=client_tokens, session_data=session_data)
    
    return _admin()

@app.route('/.well-known/stellar.toml')
def stellar_toml():
    toml_file = os.path.join(SCRIPT_DIR, "static", "stellar.toml")

    print(toml_file)
    print(os.path.exists(toml_file))
    if not os.path.exists(toml_file):
        abort(404)
    response = make_response(send_file(toml_file, mimetype='text/plain'))
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Content-Type'] = 'text/plain; charset=utf-8'
    return response

@app.route('/top_up_stellar')
def top_up_stellar():
   PINTHEON.stellar_wallet_qr = url_for('static', filename='stellar_wallet_qr.png')
   template = 'top_up.html'
   page = 'top_up'
   js=_load_js('top_up')
   qr=PINTHEON.stellar_wallet_qr

   return render_template(template, page=page, js=js, qr=qr)

@app.route('/end_session', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='json')
@require_session_state(active=True)
@require_token_verification('client_pub', 'token', source='json')
def end_session():
    data = request.get_json()
    print(data)
    PINTHEON.end_session()
    return jsonify({'authorized': False}), 200
   
@app.route('/reset_init', methods=['POST'])
@cross_origin()
@require_local_access
def reset_init():
     if PINTHEON.state == 'establishing':
          PINTHEON.init_reset()
          PINTHEON.end_session()
          admin()
        
     return jsonify({'authorized': False}), 200

@app.route('/new_node', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'launch_key', 'launch_token', 'generator_pub'], source='json')
@require_session_state(state='initialized', active=False)
@require_token_verification('client_pub', 'token', source='json')
def new_node():
    data = request.get_json()

    verifier = PINTHEON.launch_token_verifier(data['launch_key'], data['launch_token'])

    if verifier.valid() == True:
        PINTHEON.new_node()
        PINTHEON.set_client_session_pub(data['client_pub'])
        PINTHEON.set_seed(verifier.secret().strip())
        PINTHEON.set_client_node_pub(data['generator_pub'])
        established = PINTHEON.new()
        if established:
            return PINTHEON.establish_data(), 200
        else:
            return jsonify({'error': 'Insufficient Balance'}), 400
    else:
        return jsonify({'error': 'Launch Token Invalid'}), 400

@app.route('/establish', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'name', 'descriptor', 'meta_data', 'host'], source='json')
@require_session_state(state='establishing', active=True)
@require_token_verification('client_pub', 'token', source='json')
def establish():
    data = request.get_json()
    print(data)
    PINTHEON.set_node_data(data['name'], data['descriptor'], data['meta_data'], data['host'])
    PINTHEON.established()
    return PINTHEON.establish_data(), 200

@app.route('/authorize', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'auth_token', 'generator_pub'], source='json')
def authorize():
    data = request.get_json()
    if PINTHEON.session_active or not PINTHEON.state == 'idle':
        abort(403)
    elif not PINTHEON.token_not_expired(data['client_pub'], data['token']) or not PINTHEON.verify_request(data['client_pub'], data['token']) or not PINTHEON.verify_generator(data['generator_pub'], data['auth_token']):
        raise Unauthorized()
    else:
        PINTHEON.set_client_session_pub(data['client_pub'])
        PINTHEON.authorized()
        dash_data = PINTHEON.get_dashboard_data()
        if dash_data is None:
            return jsonify({'error': 'Cannot get dash data'}), 400
        else:
            return dash_data, 200

@app.route('/authorized', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'auth_token', 'client_pub'], source='json')
def authorized():
    data = request.get_json()
    print(data)
    if not PINTHEON.token_not_expired(data['client_pub'], data['token']) and (not PINTHEON.session_active or not PINTHEON.state == 'idle'):
        abort(403)
    elif not PINTHEON.verify_authorization(data['client_pub'], data['auth_token']):
        raise Unauthorized()
    else:
        dash_data = PINTHEON.get_dashboard_data()
        if dash_data is None:
            return jsonify({'error': 'Cannot get dash data'}), 400
        else:
            print('@@@@@')
            print(dash_data)
            return dash_data, 200

@app.route('/deauthorize', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='json')
@require_session_state(active=True)
@require_token_verification('client_pub', 'token', source='json')
def deauthorize():
    data = request.get_json()
    print(data)
    PINTHEON.deauthorized()
    PINTHEON.end_session()
    return jsonify({'authorized': False}), 200

@app.route('/upload', methods=['POST'])
@cross_origin()
@require_local_access
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def upload():
    required = ['token', 'client_pub']
    encrypted = request.form['encrypted']
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    print(encrypted)
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
    return _handle_upload(required, request, False, False, encrypted)

@app.route('/api_upload', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['access_token'], source='form')
def api_upload():
    token = request.form['access_token']
    encrypted = request.form['encrypted']
    if not PINTHEON.authorize_access_token(token):
        abort(403)
    else:
        required = ['access_token']
        return _handle_upload(required=required, request=request, is_logo=False, is_bg_img=False, encrypted=encrypted, return_file_info=True)

@app.route('/update_logo', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_logo():
    file = request.files['file']
    cid = None
    if PINTHEON.file_name_exists(file.filename, file.mimetype):
        PINTHEON.update_file_as_logo(file.filename)
    else:
        files = _handle_upload(required=['token', 'client_pub'], request=request, is_logo=True)
        cid = _get_file_cid(file, files)
    if cid is not None:
        PINTHEON.logo_url = _ensure_protocol(PINTHEON.url_host)+'/ipfs/'+cid
        PINTHEON.update_node_data()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/update_gateway', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'gateway'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_gateway():
    host = request.form['gateway']
    PINTHEON.url_host = host
    if '/ipfs/' in PINTHEON.logo_url:
        cid = PINTHEON.logo_url.split('/ipfs/')[-1]
        PINTHEON.logo_url = _ensure_protocol(PINTHEON.url_host)+'/ipfs/'+cid
    PINTHEON.update_node_data()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/remove_file', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'cid'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def remove_file():
    ipfs_response = PINTHEON.remove_file_from_ipfs(request.form['cid'])
    if ipfs_response is None:
        return jsonify({'error': 'File not removed'}), 400
    else:
        return ipfs_response

@app.route('/tokenize_file', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'cid', 'allocation'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def tokenize_file():
    file_data = PINTHEON.file_data_from_cid(request.form['cid'])
    if len(file_data['ContractID']) > 0:
        return jsonify({'error': 'File already tokenized', 'success': False}), 400
    else:
        contract_result = PINTHEON.deploy_ipfs_token(file_data['Name'], request.form['cid'], file_data['Name'], PINTHEON.url_host)
        print(contract_result)
        if isinstance(contract_result, dict) and not contract_result.get('success', True):
            data = PINTHEON.get_dashboard_data() or {}
            data['transaction_data'] = None
            data['error'] = contract_result.get('error', 'Contract deployment failed')
            data['success'] = False
            return jsonify(data), 400
        contract_id = contract_result['address'] if isinstance(contract_result, dict) else contract_result
        PINTHEON.update_file_contract_id(request.form['cid'], contract_id)
        transaction_result = PINTHEON.ipfs_custodial_mint(request.form['cid'], contract_id, int(request.form['allocation']))
        data = PINTHEON.get_dashboard_data() or {}
        # Always return the original transaction structure
        if isinstance(transaction_result, dict) and 'tx' in transaction_result:
            data['transaction_data'] = transaction_result['tx']
        else:
            data['transaction_data'] = transaction_result
        if isinstance(transaction_result, dict) and not transaction_result.get('success', True):
            data['error'] = transaction_result.get('error', 'Minting failed')
            data['success'] = False
            return jsonify(data), 400
        data['success'] = True
        return jsonify(data)

@app.route('/send_file_token', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'cid', 'amount', 'to_address'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def send_file_token():
    file_data = PINTHEON.file_data_from_cid(request.form['cid'])
    amount = int(request.form['amount'])
    if amount > 0 and len(file_data['ContractID']) > 0:
        transaction_result = PINTHEON.ipfs_token_send(request.form['cid'], file_data['ContractID'], request.form['to_address'], amount)
        data = PINTHEON.get_dashboard_data() or {}
        # Always return the original transaction structure
        if isinstance(transaction_result, dict) and 'tx' in transaction_result:
            data['transaction_data'] = transaction_result['tx']
        else:
            data['transaction_data'] = transaction_result
        if isinstance(transaction_result, dict) and not transaction_result.get('success', True):
            data['error'] = transaction_result.get('error', 'Token send failed')
            data['success'] = False
            return jsonify(data), 400
        data['success'] = True
        return jsonify(data)

@app.route('/send_token', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['name', 'token_id', 'client_pub', 'token_id', 'amount', 'to_address'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def send_token():
    amount = int(request.form['amount'])
    if amount > 0:
        transaction_result = PINTHEON.token_send(request.form['token_id'], request.form['to_address'], amount)
        data = PINTHEON.get_dashboard_data() or {}
        # Always return the original transaction structure
        if isinstance(transaction_result, dict) and 'tx' in transaction_result:
            data['transaction_data'] = transaction_result['tx']
        else:
            data['transaction_data'] = transaction_result
        if isinstance(transaction_result, dict) and not transaction_result.get('success', True):
            data['error'] = transaction_result.get('error', 'Token send failed')
            data['success'] = False
            return jsonify(data), 400
        data['success'] = True
        return jsonify(data)

@app.route('/publish_file', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['name', 'cid', 'client_pub', 'token', 'encrypted', 'reciever_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def publish_file():
    encrypted = request.form['encrypted']
    cid = request.form['cid']
    data = None
    if encrypted == 'true':
        reciever_pub = request.form['reciever_pub']
        transaction_result = PINTHEON.publish_encrypted_file(reciever_pub, cid)
    else:
        transaction_result = PINTHEON.publish_file(cid)
    data = PINTHEON.get_dashboard_data() or {}
    # Always return the original transaction structure
    if isinstance(transaction_result, dict) and 'transaction' in transaction_result:
        data['transaction_data'] = transaction_result['transaction']
    else:
        data['transaction_data'] = transaction_result
    if isinstance(transaction_result, dict) and not transaction_result.get('successful', True):
        data['error'] = transaction_result.get('error', 'Publish failed')
        data['success'] = False
        return jsonify(data), 400
    data['success'] = True
    return jsonify(data)

@app.route('/add_to_namespace', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'cid'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def add_to_namespace():
    if 'name' not in request.form:
        ipfs_response = PINTHEON.add_cid_to_ipns(request.form['cid'], request.form['name'])
    else:
        ipfs_response = PINTHEON.add_cid_to_ipns(request.form['cid'])
    if ipfs_response is None:
        return jsonify({'error': 'File not removed'}), 400
    else:
        return ipfs_response

@app.route('/add_access_token', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'name', 'stellar_25519_pub', 'timestamped', 'timestamp'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def add_access_token():
    name = request.form['name']
    timestamped = request.form['timestamped']
    timestamp = int(request.form['timestamp'])

    if timestamped == 'true':
        timestamped = True
    else:
        timestamped = False

    stellar_25519_pub = request.form['stellar_25519_pub']
    token = PINTHEON.add_access_token(name, stellar_25519_pub, timestamped=timestamped, timestamp=timestamp)
    if token is None:
        return jsonify({'error': 'Cannot create new access token'}), 400
    else:
        return jsonify({'access_token': token}), 200

@app.route('/remove_access_token', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'stellar_25519_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def remove_access_token():
    stellar_25519_pub = request.form['stellar_25519_pub']
    PINTHEON.remove_access_token(stellar_25519_pub)
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/dashboard_data', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def dashboard_data():
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/update_theme', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'theme'], source='json')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='json')
def update_theme():
    req = request.get_json()
    PINTHEON.theme = req['theme']
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200
    

@app.route('/update_homepage_type', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'homepage_type'], source='json')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='json')
def update_homepage_type():
    req = request.get_json()
    PINTHEON.homepage_type = req['homepage_type']
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'success': False, 'error': 'Cannot get dash data'}), 400
    else:
        data['success'] = True
        return data, 200
    
@app.route('/update_homepage_hash', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'hash'], source='json')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='json')
def update_homepage_hash():
    req = request.get_json()
    PINTHEON.homepage_hash = req['hash']
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'success': False, 'error': 'Cannot get dash data'}), 400
    else:
        data['success'] = True
        return data, 200
    
@app.route('/hash_is_html', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub', 'hash'], source='json')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='json')
def hash_is_html():
    req = request.get_json()
    result = PINTHEON.is_html_file(req['hash'])

    if result is False:
        return jsonify({'success': False, 'message': 'File not found, ot not valid.'}), 400
    else:
        return jsonify({'success': True, 'message': 'File is html.'})

@app.route('/update_bg_img', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_bg_img():
    file = request.files['file']
    cid = None
    PINTHEON.all_file_info()
    print(file.mimetype)
    if PINTHEON.file_name_exists(file.filename, file.mimetype):
        print('HERE!!!')
        files = PINTHEON.update_file_as_bg_img(file.filename)
        cid = _get_file_cid(file, files)
    else:
        files = _handle_upload(required=['token', 'client_pub'], request=request, is_bg_img=True)
        cid = _get_file_cid(file, files)
    if cid is not None:
        PINTHEON.bg_img = _ensure_protocol(PINTHEON.url_host)+'/ipfs/'+cid
        PINTHEON.update_node_data()
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/remove_bg_img', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def remove_bg_img():
    PINTHEON.remove_file_as_bg_img()
    PINTHEON.bg_img = None
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/upload_homepage', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def upload_homepage():
    """Upload a ZIP file containing the custom homepage"""
    print(f"DEBUG: upload_homepage called")
    print(f"DEBUG: request.files keys: {list(request.files.keys())}")
    print(f"DEBUG: request.form keys: {list(request.form.keys())}")
    print(f"DEBUG: PINTHEON.state: {PINTHEON.state}")
    print(f"DEBUG: PINTHEON.session_active: {PINTHEON.session_active}")
    
    if 'file' not in request.files:
        print(f"DEBUG: No file in request.files")
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    print(f"DEBUG: file.filename: {file.filename}")
    print(f"DEBUG: file.mimetype: {file.mimetype}")
    
    if file.filename == '':
        print(f"DEBUG: Empty filename")
        return jsonify({'error': 'No file selected'}), 400
    
    # Check if it's a ZIP file
    if not file.filename.lower().endswith('.zip'):
        print(f"DEBUG: Not a ZIP file: {file.filename}")
        return jsonify({'error': 'Please upload a ZIP file containing your website'}), 400
    
    # Save the ZIP file temporarily and extract it
    try:
        # Save ZIP file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            file.save(tmp_file.name)
            zip_path = tmp_file.name
        
        print(f"DEBUG: Saved ZIP to {zip_path}")
        
        # Extract ZIP file
        if _extract_zip_to_homepage(zip_path):
            print(f"DEBUG: ZIP extraction successful")
            # Clean up the temporary ZIP file
            os.remove(zip_path)
            
            # Check if an index file was created
            if _custom_homepage_exists():
                print(f"DEBUG: Custom homepage exists")
                return jsonify({'success': True, 'message': 'Homepage uploaded successfully'}), 200
            else:
                print(f"DEBUG: No index file found")
                return jsonify({'error': 'No index.html, index.htm, or index.php found in the ZIP file'}), 400
        else:
            print(f"DEBUG: ZIP extraction failed")
            # Clean up the temporary ZIP file even if extraction failed
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return jsonify({'error': 'Failed to extract ZIP file'}), 400
            
    except Exception as e:
        print(f"DEBUG: Exception in upload_homepage: {str(e)}")
        # Clean up the temporary ZIP file in case of any error
        if 'zip_path' in locals() and os.path.exists(zip_path):
            os.remove(zip_path)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 400

@app.route('/remove_homepage', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def remove_homepage():
    """Remove the custom homepage"""
    try:
        if os.path.exists(CUSTOM_HOMEPAGE_PATH):
            shutil.rmtree(CUSTOM_HOMEPAGE_PATH)
            os.makedirs(CUSTOM_HOMEPAGE_PATH, exist_ok=True)
        return jsonify({'success': True, 'message': 'Homepage removed successfully'}), 200
    except Exception as e:
        return jsonify({'error': f'Error removing homepage: {str(e)}'}), 400

@app.route('/homepage_status', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def homepage_status():
    """Get the status of the custom homepage"""
    exists = _custom_homepage_exists()
    if exists:
        index_file = _get_custom_homepage_file()
        return jsonify({
            'exists': True,
            'index_file': index_file,
            'files': os.listdir(CUSTOM_HOMEPAGE_PATH) if os.path.exists(CUSTOM_HOMEPAGE_PATH) else []
        }), 200
    else:
        return jsonify({'exists': False}), 200

@app.route('/api_upload_homepage', methods=['POST'])
@cross_origin()
@require_local_access
@require_fields(['access_token'], source='form')
def api_upload_homepage():
    """Upload a ZIP file containing the custom homepage using access token authentication"""
    token = request.form['access_token']
    if not PINTHEON.authorize_access_token(token):
        abort(403)
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check if it's a ZIP file
    if not file.filename.lower().endswith('.zip'):
        return jsonify({'error': 'Please upload a ZIP file containing your website'}), 400
    
    # Save the ZIP file temporarily and extract it
    try:
        # Save ZIP file to a temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
            file.save(tmp_file.name)
            zip_path = tmp_file.name
        
        # Extract ZIP file
        if _extract_zip_to_homepage(zip_path):
            # Clean up the temporary ZIP file
            os.remove(zip_path)
            
            # Check if an index file was created
            if _custom_homepage_exists():
                return jsonify({'success': True, 'message': 'Homepage uploaded successfully'}), 200
            else:
                return jsonify({'error': 'No index.html, index.htm, or index.php found in the ZIP file'}), 400
        else:
            # Clean up the temporary ZIP file even if extraction failed
            if os.path.exists(zip_path):
                os.remove(zip_path)
            return jsonify({'error': 'Failed to extract ZIP file'}), 400
            
    except Exception as e:
        # Clean up the temporary ZIP file in case of any error
        if 'zip_path' in locals() and os.path.exists(zip_path):
            os.remove(zip_path)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 400

@app.route('/api/heartbeat', methods=['GET'])
@cross_origin()
@require_local_access
def api_heartbeat():
    if PINTHEON.logged_in and PINTHEON.session_active:
        PINTHEON.update_xlm_balance()
        PINTHEON.update_opus_balance()
        data = PINTHEON.get_dashboard_data()
        if data != None:
            return data, 200
        else:
            return jsonify({'status': 'ok'}), 200
    else:
        return jsonify({'status': 'ok'}), 200
        

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)