import os
import requests
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for
from flask_cors import CORS, cross_origin
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, HTTPException
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query
from platformdirs import *
from pintheonMachine import PintheonMachine
from pymacaroons import Macaroon, Verifier, MACAROON_V1, MACAROON_V2

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

PINTHEON = PintheonMachine(static_path=STATIC_PATH, db_path=DB_PATH, debug=True, fake_ipfs=True)
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
        file_name = f"{file.filename}.7z",
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
   hsh = PINTHEON.hash_key('bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=')
   print(PINTHEON.hash_key(hsh))
   m = Macaroon(
            location='',
            identifier='PINTHEON_LAUNCH_TOKEN',
            key='bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=',
            version=MACAROON_V1
        )
   print(m.identifier)
   print('-----------------------------------')
   print(m.serialize())
   print(PINTHEON.state)
   print(request.headers)
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
def end_session():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PINTHEON.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
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
def new_node():
   required = ['token', 'client_pub', 'seed_cipher', 'generator_pub']
   data = request.get_json()

   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PINTHEON.state == 'initialized':  # PINTHEON must be initialized
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
        PINTHEON.new_node()
        PINTHEON.set_client_session_pub(data['client_pub'])
        PINTHEON.set_seed_cipher(data['seed_cipher'])
        PINTHEON.set_client_node_pub(data['generator_pub'])
        PINTHEON.new()
        
   return PINTHEON.establish_data(), 200
        

@app.route('/establish', methods=['POST'])
@cross_origin()
def establish():
   required = ['token', 'client_pub', 'name', 'descriptor', 'meta_data', 'host']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PINTHEON.state == 'establishing':  # PINTHEON must be establishing
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(data['client_pub'], data['token']):  # client must send valid session token
        raise Unauthorized()  # Unauthorized

   else:
        PINTHEON.set_node_data(data['name'], data['descriptor'], data['meta_data'], data['host'])
        PINTHEON.established()
        
   return PINTHEON.establish_data(), 200
   

@app.route('/authorize', methods=['POST'])
@cross_origin()
def authorize():
   required = ['token', 'client_pub', 'auth_token', 'generator_pub']
   data = request.get_json()

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.token_not_expired(data['client_pub'], data['token']) or not PINTHEON.verify_request(data['client_pub'], data['token']) or not PINTHEON.verify_generator(data['generator_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        PINTHEON.set_client_session_pub(data['client_pub'])
        PINTHEON.authorized()
        data = PINTHEON.get_dashboard_data()
        if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
        else:
          return data, 200
   

@app.route('/authorized', methods=['POST'])
@cross_origin()
def authorized():
   required = ['token', 'auth_token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PINTHEON.token_not_expired(data['client_pub'], data['token']) and (not PINTHEON.session_active or not PINTHEON.state == 'idle'):  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_authorization(data['client_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
     data = PINTHEON.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200  
   

@app.route('/deauthorize', methods=['POST'])
@cross_origin()
def deauthorize():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PINTHEON.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
        PINTHEON.deauthorized()
        PINTHEON.end_session()
        
        return jsonify({'authorized': False}), 200
   

@app.route('/upload', methods=['POST'])
@cross_origin()
def upload():
   required = ['token', 'client_pub']
   encrypted = request.form['encrypted']
   print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
   print(encrypted)
   print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@')
   return _handle_upload(required, request, False, False, encrypted)

@app.route('/api_upload', methods=['POST'])
@cross_origin()
def upload():
   required = ['access_token']
   token = request.form['access_token']
   encrypted = request.form['encrypted']
   if not PINTHEON.auth_token(token):
       abort(Forbidden())
       
   return _handle_upload(required, request, False, False, encrypted)

@app.route('/update_logo', methods=['POST'])
@cross_origin()
def update_logo():
   required = ['token', 'client_pub']
   file = request.files['file']

   if PINTHEON.file_exists(file.filename, file.mimetype):
          PINTHEON.update_file_as_logo(file.filename)
   else:
        files = _handle_upload(required=required, request=request, is_logo=True)
        cid = _get_file_cid(file, files)

   if cid != None:
        PINTHEON.logo_url = PINTHEON.url_host+'/ipfs/'+cid
        data = PINTHEON.update_node_data()

   data = PINTHEON.get_dashboard_data()
   if data == None:
        return jsonify({'error': 'Cannot get dash data'}), 400
   else:
        return data, 200
   
@app.route('/update_gateway', methods=['POST'])
@cross_origin()
def update_gateway():
   required = ['token', 'client_pub', 'gateway']
   host = request.form['gateway']

   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400
        
   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        
     PINTHEON.url_host = host
     
     if '/ipfs/' in PINTHEON.logo_url:
         cid = PINTHEON.logo_url.split('/ipfs/')[-1]
         PINTHEON.logo_url = PINTHEON.url_host+'/ipfs/'+cid
         PINTHEON.update_node_data()
     
     data = PINTHEON.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200

@app.route('/remove_file', methods=['POST'])
@cross_origin()
def remove_file():
   required = ['token', 'client_pub', 'cid']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        ipfs_response = PINTHEON.remove_file_from_ipfs(request.form['cid'])

        if ipfs_response == None:
                return jsonify({'error': 'File not removed'}), 400
        else:
            return ipfs_response
        
@app.route('/tokenize_file', methods=['POST'])
@cross_origin()
def tokenize_file():
   required = ['token', 'client_pub', 'cid', 'allocation']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        file_data = PINTHEON.file_data_from_cid(request.form['cid'])
        if len(file_data['ContractID']) > 0:
            return jsonify({'error': 'File already tokenized'}), 400
        else:
          print(request.form['allocation'])
          contract_id = PINTHEON.deploy_ipfs_token(file_data['Name'], request.form['cid'], file_data['Name'], PINTHEON.url_host)
          PINTHEON.update_file_contract_id(request.form['cid'], contract_id)
          transaction_data = PINTHEON.ipfs_custodial_mint(request.form['cid'], contract_id, int(request.form['allocation']))
          data = PINTHEON.get_dashboard_data()
          data['transaction_data'] = transaction_data

          if data == None:
                    return jsonify({'error': 'File data not updated'}), 400
          else:
               return data
        
@app.route('/send_file_token', methods=['POST'])
@cross_origin()
def send_file_token():
   required = ['token', 'client_pub', 'cid', 'amount', 'to_address']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        file_data = PINTHEON.file_data_from_cid(request.form['cid'])
        amount = int(request.form['amount'])
        if amount > 0 and len(file_data['ContractID']) > 0:
          transaction_data = PINTHEON.ipfs_token_send(request.form['cid'], file_data['ContractID'], request.form['to_address'], amount)
          data = PINTHEON.get_dashboard_data()
          data['transaction_data'] = transaction_data

          if data == None:
                    return jsonify({'error': 'File data not updated'}), 400
          else:
               return data
          
@app.route('/send_token', methods=['POST'])
@cross_origin()
def send_token():
   required = ['name', 'token_id', 'client_pub', 'token_id', 'amount', 'to_address']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        amount = int(request.form['amount'])
        if amount > 0 :
          transaction_data = PINTHEON.token_send(request.form['token_id'], request.form['to_address'], amount)
          data = PINTHEON.get_dashboard_data()
          data['transaction_data'] = transaction_data

          if data == None:
                    return jsonify({'error': 'File data not updated'}), 400
          else:
               return data
          
@app.route('/publish_file', methods=['POST'])
@cross_origin()
def publish_file():
   required = ['name', 'cid', 'client_pub', 'token', 'encrypted', 'reciever_pub']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        encrypted = request.form['encrypted']
        cid = request.form['cid']
        data = None
        if encrypted is True:
            reciever_pub = request.form['reciever_pub']
            transaction_data = PINTHEON.publish_encrypted_file(reciever_pub, cid)
            data = PINTHEON.get_dashboard_data()
            data['transaction_data'] = transaction_data
        else:
            transaction_data = PINTHEON.publish_file(cid)
            data = PINTHEON.get_dashboard_data()
            data['transaction_data'] = transaction_data

        if data == None:
               return jsonify({'error': 'File data not updated'}), 400
        else:
               return data
        
@app.route('/add_to_namespace', methods=['POST'])
@cross_origin()
def add_to_namespace():
   required = ['token', 'client_pub', 'cid']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        if 'name' not in request.form:
          ipfs_response = PINTHEON.add_cid_to_ipns(request.form['cid'], request.form['name'])
        else:
            ipfs_response = PINTHEON.add_cid_to_ipns(request.form['cid'])

        if ipfs_response == None:
                return jsonify({'error': 'File not removed'}), 400
        else:
            return ipfs_response
        
@app.route('/add_access_token', methods=['POST'])
@cross_origin()
def add_access_token():
   required = ['token', 'client_pub', 'name', 'stellar_25519_pub']

   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400
        
   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
       name = request.form['name']
       stellar_25519_pub = request.form['stellar_25519_pub']
       token = PINTHEON.add_access_token(name, stellar_25519_pub)

       if token == None:
                return jsonify({'error': 'Cannot create new access token'}), 400
       else:
            return jsonify({'access_token': token}), 200
       
@app.route('/remove_access_token', methods=['POST'])
@cross_origin()
def remove_access_token():
   required = ['token', 'client_pub', 'stellar_25519_pub']

   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400
        
   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
       stellar_25519_pub = request.form['stellar_25519_pub']
       PINTHEON.remove_access_token(stellar_25519_pub)
       data = PINTHEON.get_dashboard_data()

       if data == None:
                return jsonify({'error': 'Cannot get dash data'}), 400
       else:
            return data, 200
        
@app.route('/dashboard_data', methods=['POST'])
@cross_origin()
def dashboard_data():
   required = ['token', 'client_pub']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        data = PINTHEON.get_dashboard_data()

        if data == None:
                return jsonify({'error': 'Cannot get dash data'}), 400
        else:
            return data, 200
        
@app.route('/update_theme', methods=['POST'])
@cross_origin()
def update_theme():
   required = ['token', 'client_pub', 'theme']
   req = request.get_json()

   if not _payload_valid(required, req):
        abort(400)  # Bad Request
   elif not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(req['client_pub'], req['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
   
     PINTHEON.theme = req['theme']
     PINTHEON.update_customization()
     data = PINTHEON.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200
     
@app.route('/update_bg_img', methods=['POST'])
@cross_origin()
def update_bg_img():
   required = ['token', 'client_pub']
   file = request.files['file']
   cid = None

   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400
        
   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
     PINTHEON.all_file_info()

     print(file.mimetype)

     if PINTHEON.file_exists(file.filename, file.mimetype):
          print('HERE!!!')
          files = PINTHEON.update_file_as_bg_img(file.filename)
          cid = _get_file_cid(file, files)
     else:
          files = _handle_upload(required=required, request=request, is_bg_img=True)
          cid = _get_file_cid(file, files)

     if cid != None:
          PINTHEON.bg_img = PINTHEON.url_host+'/ipfs/'+cid
          data = PINTHEON.update_node_data()
   
     PINTHEON.update_customization()
     data = PINTHEON.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200
     
@app.route('/remove_bg_img', methods=['POST'])
@cross_origin()
def remove_bg_img():
   required = ['token', 'client_pub']


   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400
        
   if not PINTHEON.session_active or not PINTHEON.state == 'idle':  # PINTHEON must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PINTHEON.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
   
     PINTHEON.remove_file_as_bg_img()
     PINTHEON.bg_img = None
     PINTHEON.update_customization()
     data = PINTHEON.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200
        

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)