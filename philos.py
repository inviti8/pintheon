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

PHILOS = PhilosMachine(STATIC_PATH, DB_PATH)
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

def _handle_upload(required, request):
    if 'file' not in request.files:
        return "No file uploaded", 400
     
    file = request.files['file']
     
    for field in required:
        if field not in request.form:
            return "Missing or empty value for field: {}".format(field), 400

    if not PHILOS.session_active or not PHILOS.state == 'idle':  # PHILOS must be idle
        abort(Forbidden())  # Forbidden
    
    elif not PHILOS.verify_request(request.form['client_pub'], request.form['token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
    else:
        file_data = file.read()
        ipfs_response = PHILOS.add_file_to_ipfs(file.filename, file.mimetype, file_data)

        if ipfs_response == None:
                return jsonify({'error': 'File not added'}), 400
        else:
            return ipfs_response


##ERROR HEANDLING##
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
def home():
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
   print('-----------------------------------')
   pub = PHILOS.session_pub
   if not PHILOS.logged_in:
       pub = PHILOS.new_session()
       
   PHILOS.logo_url = url_for('static', filename='hvym_logo.png')
   template = PHILOS.view_template
   components=_load_components(PHILOS.view_components)
   page = PHILOS.active_page
   js=_load_js(PHILOS.view_components)
   logo=PHILOS.logo_url
   shared_dialogs=_load_components(PHILOS.shared_dialogs)
   shared_dialogs_js=_load_js(PHILOS.shared_dialogs)
   client_tokens= _load_js('macaroons_js_bundle')
   
   session_data = { 'pub': pub, 'generator_pub': PHILOS.node_pub, 'time': PHILOS.session_ends, 'nonce': PHILOS.session_nonce }
   return render_template(template, page=page, components=components, js=js, logo=logo, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js, client_tokens=client_tokens, session_data=session_data)

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
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):  # client must send valid launch token
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
          home()
        
     return jsonify({'authorized': False}), 200

@app.route('/new_node', methods=['POST'])
@cross_origin()
def new_node():
   required = ['token', 'client_pub', 'launch_token', 'seed_cipher', 'generator_pub']
   data = request.get_json()

   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PHILOS.state == 'initialized':  # PHILOS must be initialized
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']) or not PHILOS.verify_launch(data['launch_token']):  # client must send valid launch token
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
   required = ['token', 'client_pub', 'name', 'descriptor', 'meta_data']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not PHILOS.state == 'establishing':  # PHILOS must be establishing
        abort(Forbidden())  # Forbidden
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):  # client must send valid session token
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.set_node_data(data['name'], data['descriptor'], data['meta_data'])
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
        return jsonify({'name': PHILOS.node_name, 'descriptor': PHILOS.node_descriptor, 'logo': PHILOS.logo_url, 'nonce': PHILOS.auth_nonce, 'expires': str(PHILOS.session_ends), 'authorized': True}), 200
   

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
        return jsonify({'name': PHILOS.node_name, 'descriptor': PHILOS.node_descriptor, 'logo': PHILOS.logo_url, 'nonce': PHILOS.auth_nonce, 'file_list': PHILOS.get_files(), 'expires': str(PHILOS.session_ends), 'authorized': True}), 200
   

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
    
   elif not PHILOS.verify_request(data['client_pub'], data['token']):  # client must send valid launch token
        raise Unauthorized()  # Unauthorized

   else:
        PHILOS.deauthorized()
        PHILOS.end_session()
        
        return jsonify({'authorized': False}), 200
   

@app.route('/upload', methods=['POST'])
@cross_origin()
def upload():
   required = ['token', 'client_pub']
   return _handle_upload(required, request)

@app.route('/upate_logo', methods=['POST'])
@cross_origin()
def update_logo():
   required = ['token', 'client_pub']
   response = _handle_upload(required, request)
   if response.status_code == 200:
       PHILOS.logo_url
   return response

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
        ipfs_response = PHILOS.get_dashboard_data()

        if ipfs_response == None:
                return jsonify({'error': 'File not removed'}), 400
        else:
            return ipfs_response
        
@app.route('/data', methods=['POST'])
def create_data():
   data = request.get_json()
   # Here you would normally save the data to a database
   return jsonify(message='Data received', data=data), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)