import os
import requests
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for, send_file, make_response
from flask_cors import CORS, cross_origin
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, HTTPException
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query
from platformdirs import *
from pintheonMachine import PintheonMachine
from StellarTomlGenerator import StellarTomlGenerator
from pymacaroons import Macaroon, Verifier, MACAROON_V1, MACAROON_V2
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
MEGABYTE = (2 ** 10) ** 2
app.config['MAX_CONTENT_LENGTH'] = None
app.config['MAX_FORM_MEMORY_SIZE'] = 200 * MEGABYTE

CORS(app)

SCRIPT_DIR = os.path.abspath( os.path.dirname( __file__ ) )
STATIC_PATH = os.path.join(SCRIPT_DIR, "static")
DB_PATH = os.path.join(SCRIPT_DIR, "enc_db.json")
COMPONENT_PATH = os.path.join(SCRIPT_DIR, "components")

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
            if source == 'json':
                data = request.get_json()
                if not _payload_valid(fields, data):
                    abort(400)
                return f(*args, **kwargs)
            elif source == 'form':
                for field in fields:
                    if field not in request.form:
                        return "Missing or empty value for field: {}".format(field), 400
                return f(*args, **kwargs)
            else:
                abort(400)
        return wrapper
    return decorator

def require_session_state(state='idle', active=True):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if active and not PINTHEON.session_active:
                abort(403)
            if state and not PINTHEON.state == state:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def require_token_verification(pub_field, token_field, source='json'):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if source == 'json':
                data = request.get_json()
                if not PINTHEON.verify_request(data[pub_field], data[token_field]):
                    raise Unauthorized()
            elif source == 'form':
                if not PINTHEON.verify_request(request.form[pub_field], request.form[token_field]):
                    raise Unauthorized()
            else:
                abort(400)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def _handle_upload(required, request, is_logo=False, is_bg_img=False, encrypted=False):
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

    ipfs_response = PINTHEON.add_file_to_ipfs(file_name=file_name, file_type=file_type, file_data=file_data, is_logo=is_logo, is_bg_img=is_bg_img, encrypted=encrypted, reciever_pub=reciever_pub)

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
        


##ERROR HANDLING##
class Forbidden(HTTPException):
    code = 403
    description = 'You do not have the permission to perform this action'

class Unauthorized(HTTPException):
    code = 401
    description = 'Invalid Credentials'

def _on_failure_error():
    PINTHEON.end_session()

@app.errorhandler(401)
def unauthorized_access(e):
    # handle Unauthorized access here
    _on_failure_error()
    return 'Access Denied', 401

@app.errorhandler(Forbidden)
def handle_forbidden(e):
    # handle forbidden action here
    _on_failure_error()
    return 'Permission Denied', 403

@app.errorhandler(500)
def unauthorized_access(e):
    # handle server error here
    _on_failure_error()
    return 'Server Error', 500

##ROUTES## 
@app.route('/admin')
def admin():
   print('-----------------------------------')
   print(PINTHEON.state)
   print(request.headers)
   print(PINTHEON.soroban_online())
   print('-----------------------------------')

   PINTHEON.logo_url = url_for('static', filename='hvym_logo.png')
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
def reset_init():
     if PINTHEON.state == 'establishing':
          PINTHEON.init_reset()
          PINTHEON.end_session()
          admin()
        
     return jsonify({'authorized': False}), 200

@app.route('/new_node', methods=['POST'])
@cross_origin()
@require_fields(['token', 'client_pub', 'seed_cipher', 'generator_pub'], source='json')
@require_session_state(state='initialized', active=False)
@require_token_verification('client_pub', 'token', source='json')
def new_node():
    data = request.get_json()
    print(data)
    PINTHEON.new_node()
    PINTHEON.set_client_session_pub(data['client_pub'])
    PINTHEON.set_seed_cipher(data['seed_cipher'])
    PINTHEON.set_client_node_pub(data['generator_pub'])
    established = PINTHEON.new()
    if established:
        return PINTHEON.establish_data(), 200
    else:
        return jsonify({'error': 'Insufficient Balance'}), 400

@app.route('/establish', methods=['POST'])
@cross_origin()
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
@require_fields(['access_token'], source='form')
def api_upload():
    token = request.form['access_token']
    encrypted = request.form['encrypted']
    if not PINTHEON.auth_token(token):
        abort(403)
    else:
        required = ['access_token']
        return _handle_upload(required, request, False, False, encrypted)

@app.route('/update_logo', methods=['POST'])
@cross_origin()
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_logo():
    file = request.files['file']
    cid = None
    if PINTHEON.file_exists(file.filename, file.mimetype):
        PINTHEON.update_file_as_logo(file.filename)
    else:
        files = _handle_upload(required=['token', 'client_pub'], request=request, is_logo=True)
        cid = _get_file_cid(file, files)
    if cid is not None:
        PINTHEON.logo_url = PINTHEON.url_host+'/ipfs/'+cid
        PINTHEON.update_node_data()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/update_gateway', methods=['POST'])
@cross_origin()
@require_fields(['token', 'client_pub', 'gateway'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_gateway():
    host = request.form['gateway']
    PINTHEON.url_host = host
    if '/ipfs/' in PINTHEON.logo_url:
        cid = PINTHEON.logo_url.split('/ipfs/')[-1]
        PINTHEON.logo_url = PINTHEON.url_host+'/ipfs/'+cid
        PINTHEON.update_node_data()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/remove_file', methods=['POST'])
@cross_origin()
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
@require_fields(['token', 'client_pub', 'cid', 'allocation'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def tokenize_file():
    file_data = PINTHEON.file_data_from_cid(request.form['cid'])
    if len(file_data['ContractID']) > 0:
        return jsonify({'error': 'File already tokenized', 'success': False}), 400
    else:
        contract_result = PINTHEON.deploy_ipfs_token(file_data['Name'], request.form['cid'], file_data['Name'], PINTHEON.url_host)
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
@require_fields(['token', 'client_pub', 'name', 'stellar_25519_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def add_access_token():
    name = request.form['name']
    stellar_25519_pub = request.form['stellar_25519_pub']
    token = PINTHEON.add_access_token(name, stellar_25519_pub)
    if token is None:
        return jsonify({'error': 'Cannot create new access token'}), 400
    else:
        return jsonify({'access_token': token}), 200

@app.route('/remove_access_token', methods=['POST'])
@cross_origin()
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

@app.route('/update_bg_img', methods=['POST'])
@cross_origin()
@require_fields(['token', 'client_pub'], source='form')
@require_session_state(state='idle', active=True)
@require_token_verification('client_pub', 'token', source='form')
def update_bg_img():
    file = request.files['file']
    cid = None
    PINTHEON.all_file_info()
    print(file.mimetype)
    if PINTHEON.file_exists(file.filename, file.mimetype):
        print('HERE!!!')
        files = PINTHEON.update_file_as_bg_img(file.filename)
        cid = _get_file_cid(file, files)
    else:
        files = _handle_upload(required=['token', 'client_pub'], request=request, is_bg_img=True)
        cid = _get_file_cid(file, files)
    if cid is not None:
        PINTHEON.bg_img = PINTHEON.url_host+'/ipfs/'+cid
        PINTHEON.update_node_data()
    PINTHEON.update_customization()
    data = PINTHEON.get_dashboard_data()
    if data is None:
        return jsonify({'error': 'Cannot get dash data'}), 400
    else:
        return data, 200

@app.route('/remove_bg_img', methods=['POST'])
@cross_origin()
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

@app.route('/api/heartbeat', methods=['GET'])
def api_heartbeat():
    return jsonify({'status': 'ok'}), 200
        

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)