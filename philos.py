import os
import requests
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for
from flask_cors import CORS, cross_origin
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, HTTPException
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query
from platformdirs import *
from philosMachine import PhilosMachine
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

PHILOS = PhilosMachine(static_path=STATIC_PATH, db_path=DB_PATH, debug=True, fake_ipfs=True)
PHILOS.initialize()

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
    reciever_pub = None

    if encrypted == True:
        reciever_pub = request.form['reciever_pub']
        file_data = PHILOS.stellar_shared_archive(file, reciever_pub)
        file_name = f"{file.filename}.7z",

    ipfs_response = PHILOS.add_file_to_ipfs(file_name=file_name, file_type=file.mimetype, file_data=file_data, is_logo=is_logo, is_bg_img=is_bg_img, encrypted=encrypted, reciever_pub=reciever_pub)

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
    PHILOS.end_session()

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
   hsh = PHILOS.hash_key('bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=')
   print(PHILOS.hash_key(hsh))
   m = Macaroon(
            location='',
            identifier='PHILOS_LAUNCH_TOKEN',
            key='bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=',
            version=MACAROON_V1
        )
   print(m.identifier)
   print('-----------------------------------')
   print(m.serialize())
   print(PHILOS.state)
   print(request.headers)
   print('-----------------------------------')

       
   PHILOS.logo_url = url_for('static', filename='hvym_logo.png')
   PHILOS.stellar_logo_url = url_for('static', filename='stellar_logo.png')
   stellar_light_logo = url_for('static', filename='stellar_logo_light.png')
   stellar_dark_logo = url_for('static', filename='stellar_logo_dark.png')

   if PHILOS.stellar_logo == None:
     PHILOS.stellar_set_logos(stellar_light_logo, stellar_dark_logo)
   PHILOS.stellar_wallet_qr = url_for('static', filename='stellar_wallet_qr.png')
   PHILOS.opus_logo = url_for('static', filename='opus.png')
   PHILOS.boros_logo = url_for('static', filename='boros.png')

   pub = PHILOS.session_pub
   if not PHILOS.logged_in:
       pub = PHILOS.new_session()

   template = PHILOS.view_template
   components=_load_components(PHILOS.view_components)
   page = PHILOS.active_page
   js=_load_js(PHILOS.view_components)
   logo=PHILOS.logo_url
   customization = PHILOS.get_customization()
   theme = customization['themes'][customization['current_theme']]
   bg_img = customization['bg_img']
   shared_dialogs=_load_components(PHILOS.shared_dialogs)
   shared_dialogs_js=_load_js(PHILOS.shared_dialogs)
   client_tokens= _load_js('macaroons_js_bundle')
   theme_css = url_for('static', filename=theme+'-theme.css')
   
   session_data = { 'pub': pub, 'generator_pub': PHILOS.node_pub, 'time': PHILOS.session_ends, 'nonce': PHILOS.session_nonce }
   return render_template(template, page=page, components=components, js=js, logo=logo, bg_img=bg_img, theme_css=theme_css, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js, client_tokens=client_tokens, session_data=session_data)

@app.route('/top_up_stellar')
def top_up_stellar():
   PHILOS.stellar_wallet_qr = url_for('static', filename='stellar_wallet_qr.png')
   template = 'top_up.html'
   page = 'top_up'
   js=_load_js('top_up')
   qr=PHILOS.stellar_wallet_qr

   return render_template(template, page=page, js=js, qr=qr)

@app.route('/end_session', methods=['POST'])
@cross_origin()
def end_session():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PHILOS.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.end_session()
        
        return jsonify({'authorized': False}), 200
   
@app.route('/reset_init', methods=['POST'])
@cross_origin()
def reset_init():
     if PHILOS.state == 'establishing':
          PHILOS.init_reset()
          PHILOS.end_session()
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

   elif not PHILOS.state == 'initialized':  # PHILOS must be initialized
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.new_node()
        PHILOS.set_client_session_pub(data['client_pub'])
        PHILOS.set_seed_cipher(data['seed_cipher'])
        PHILOS.set_client_node_pub(data['generator_pub'])
        PHILOS.new()
        
   return PHILOS.establish_data(), 200
        

@app.route('/establish', methods=['POST'])
@cross_origin()
def establish():
   required = ['token', 'client_pub', 'name', 'descriptor', 'meta_data', 'host']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PHILOS.state == 'establishing':  # PHILOS must be establishing
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):  # client must send valid session token
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.set_node_data(data['name'], data['descriptor'], data['meta_data'], data['host'])
        PHILOS.established()
        
   return PHILOS.establish_data(), 200
   

@app.route('/authorize', methods=['POST'])
@cross_origin()
def authorize():
   required = ['token', 'client_pub', 'auth_token', 'generator_pub']
   data = request.get_json()

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.token_not_expired(data['client_pub'], data['token']) or not PHILOS.verify_request(data['client_pub'], data['token']) or not PHILOS.verify_generator(data['generator_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        PHILOS.set_client_session_pub(data['client_pub'])
        PHILOS.authorized()
        data = PHILOS.get_dashboard_data()
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

   elif not PHILOS.token_not_expired(data['client_pub'], data['token']) and (not PHILOS.session_active or not PHILOS.state == 'idle'):  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_authorization(data['client_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
     data = PHILOS.get_dashboard_data()
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

   elif not PHILOS.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.deauthorized()
        PHILOS.end_session()
        
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

@app.route('/update_logo', methods=['POST'])
@cross_origin()
def update_logo():
   required = ['token', 'client_pub']
   file = request.files['file']

   if PHILOS.file_exists(file.filename, file.mimetype):
          PHILOS.update_file_as_logo(file.filename)
   else:
        files = _handle_upload(required=required, request=request, is_logo=True)
        cid = _get_file_cid(file, files)

   if cid != None:
        PHILOS.logo_url = PHILOS.url_host+'/ipfs/'+cid
        data = PHILOS.update_node_data()

   data = PHILOS.get_dashboard_data()
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
        
   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        
     PHILOS.url_host = host
     
     if '/ipfs/' in PHILOS.logo_url:
         cid = PHILOS.logo_url.split('/ipfs/')[-1]
         PHILOS.logo_url = PHILOS.url_host+'/ipfs/'+cid
         PHILOS.update_node_data()
     
     data = PHILOS.get_dashboard_data()
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

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        ipfs_response = PHILOS.remove_file_from_ipfs(request.form['cid'])

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

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        file_data = PHILOS.file_data_from_cid(request.form['cid'])
        if len(file_data['ContractID']) > 0:
            return jsonify({'error': 'File already tokenized'}), 400
        else:
          print(request.form['allocation'])
          contract_id = PHILOS.deploy_ipfs_token(file_data['Name'], request.form['cid'], file_data['Name'], PHILOS.url_host)
          PHILOS.update_file_contract_id(request.form['cid'], contract_id)
          transaction_data = PHILOS.ipfs_custodial_mint(request.form['cid'], contract_id, int(request.form['allocation']))
          data = PHILOS.get_dashboard_data()
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

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        file_data = PHILOS.file_data_from_cid(request.form['cid'])
        amount = int(request.form['amount'])
        if amount > 0 and len(file_data['ContractID']) > 0:
          transaction_data = PHILOS.ipfs_token_send(request.form['cid'], file_data['ContractID'], request.form['to_address'], amount)
          data = PHILOS.get_dashboard_data()
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

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        amount = int(request.form['amount'])
        if amount > 0 :
          transaction_data = PHILOS.token_send(request.form['token_id'], request.form['to_address'], amount)
          data = PHILOS.get_dashboard_data()
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

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        if 'name' not in request.form:
          ipfs_response = PHILOS.add_cid_to_ipns(request.form['cid'], request.form['name'])
        else:
            ipfs_response = PHILOS.add_cid_to_ipns(request.form['cid'])

        if ipfs_response == None:
                return jsonify({'error': 'File not removed'}), 400
        else:
            return ipfs_response
        
@app.route('/dashboard_data', methods=['POST'])
@cross_origin()
def dashboard_data():
   required = ['token', 'client_pub']
   for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        data = PHILOS.get_dashboard_data()

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
   elif not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(req['client_pub'], req['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
   
     PHILOS.theme = req['theme']
     PHILOS.update_customization()
     data = PHILOS.get_dashboard_data()
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
        
   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
     PHILOS.all_file_info()

     print(file.mimetype)

     if PHILOS.file_exists(file.filename, file.mimetype):
          print('HERE!!!')
          files = PHILOS.update_file_as_bg_img(file.filename)
          cid = _get_file_cid(file, files)
     else:
          files = _handle_upload(required=required, request=request, is_bg_img=True)
          cid = _get_file_cid(file, files)

     if cid != None:
          PHILOS.bg_img = PHILOS.url_host+'/ipfs/'+cid
          data = PHILOS.update_node_data()
   
     PHILOS.update_customization()
     data = PHILOS.get_dashboard_data()
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
        
   if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
   
     PHILOS.remove_file_as_bg_img()
     PHILOS.bg_img = None
     PHILOS.update_customization()
     data = PHILOS.get_dashboard_data()
     if data == None:
          return jsonify({'error': 'Cannot get dash data'}), 400
     else:
          return data, 200
        

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)