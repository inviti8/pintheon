import os
import requests
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, HTTPException
from pymacaroons import Macaroon, Verifier
from tinydb import TinyDB, Query
from platformdirs import *
from axielMachine import AxielMachine
from pymacaroons import Macaroon, Verifier, MACAROON_V1, MACAROON_V2

app = Flask(__name__)
app.secret_key = os.urandom(24)
xelis_wallet_dirs = PlatformDirs('xelis-blockchain', 'Xelis')

SCRIPT_DIR = os.path.abspath( os.path.dirname( __file__ ) )
STATIC_PATH = os.path.join(SCRIPT_DIR, "static")
DB_PATH = os.path.join(SCRIPT_DIR, "enc_db.json")
COMPONENT_PATH = os.path.join(SCRIPT_DIR, "components")
WALLET_PATH = xelis_wallet_dirs.user_data_dir
IPFS_API = "http://127.0.0.1:5001/api/v0"

AXIEL = AxielMachine(STATIC_PATH, DB_PATH, WALLET_PATH)
AXIEL.initialize()

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

##IPFS METHODS##
def get_stats(stat_type):
        url = f'{IPFS_API}/stats/{stat_type}?'
        response = requests.post(url);

        #return requests.post(url)
        # print('stat res : ',response.json())
        # print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400 
        
def get_peer_id():
        url = f'{IPFS_API}/config?arg=Identity.PeerID'
        response = requests.post(url);

        #return requests.post(url)
        # print(response)
        # print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400
        
def add_file_to_ipfs(file_name,file_type, file_data,moniker,account):
    url = f'{IPFS_API}/v0/add'

    files = {
        'file': (
            file_name,  # Set a dummy filename for directory parts
            file_data,
            'application/x-directory' if isinstance(file_data, dict) else 'application/octet-stream'
        )
    }

    params = {
        'quiet': 'false',
        'quieter': 'false',
        'silent': 'false',
        'progress': 'false',
        'trickle': 'false',
        'only-hash': 'false',
        'wrap-with-directory': 'false',
        'chunker': 'size-262144',
        'raw-leaves': 'false',
        'nocopy': 'false',
        'fscache': 'false',
        'cid-version': '0',
        'hash': 'sha2-256',
        'inline': 'false',
        'inline-limit': '32',
        'pin': 'true'
    }

    response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        ipfs_data = response.json()
        # print('ipfs res : ',ipfs_data)
        cid = pin_cid_to_ipfs(ipfs_data['Hash'])
     #    if cid != None:
     #            file_data = {'Name':ipfs_data['Name'], 'Hash':ipfs_data['Hash'], 'CID':cid, 'Size':ipfs_data['Size']}
     #            file_book.insert(file_data)
     #            cel_data={'Name':ipfs_data['Name'], 'Hash':ipfs_data['Hash'],'Type':file_type,'Link':('http://localhost:8080/ipfs/'+ipfs_data['Hash']),'Moniker':moniker,'Account':account }
     #            upload_data_to_celestia(cel_data)
     #            return file_book.all()
     #    else:
     #            return None
    else:
        return None
    
    
def pin_cid_to_ipfs(cid):
        # print('pin_cid_to_ipfs')
        pin_url = f'{IPFS_API}/v0/pin/add?arg={cid}'
        # print(pin_url)

        response = requests.post(pin_url)

        if response.status_code == 200:
                pin_data = response.json()
                # print(pin_data)
                return pin_data['Pins'][0]
                # Handle successful pinning response if necessary
        else:
                # Handle pinning failure if necessary
                print(response.text)
                return None
        
        
def remove_file_from_ipfs(cid):
        print('remove_file_from_ipfs')
        url = f'{IPFS_API}/v0/pin/rm?arg={cid}&recursive=true'
        print(url)
        response = requests.post(url)

        print(response.text)

        if response.status_code == 200:
                url = f'{IPFS_API}/v0/repo/gc'
                data = response.json()
                print(data)
                response = requests.post(url)
                if response.status_code == 200:
                        print(response)
                        print(response.text)
                        ipfs_data = response.text
                        print(ipfs_data)
                        File = Query()
                        #file_book.remove(File.CID == cid)
                        #return file_book.all()
                else:
                        return None
        else:
                return None
        

def get_file_list():
        url = f'{IPFS_API}/v0/files/ls'
        response = requests.post(url);

        #return requests.post(url)
        print(response)
        print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400
        
        
def get_peer_list():
        url = f'{IPFS_API}/v0/bootstrap/list'
        response = requests.post(url);

        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400 


##ERROR HEANDLING##
class Forbidden(HTTPException):
    code = 403
    description = 'You do not have the permission to perform this action'

class Unauthorized(HTTPException):
    code = 401
    description = 'Invalid Credentials'

def _on_failure_error():
    AXIEL.end_session()

@app.errorhandler(401)
def unauthorized_access(e):
    # handle Unauthorized access here
    _on_failure_error()
    return 'Access Denied', 401

@app.errorhandler(Unauthorized)
def handle_unauthorized(e):
    # handle unauthorized access here
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
@app.route('/')
def home():
   hsh = AXIEL.hash_key('bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=')
   print(AXIEL.hash_key(hsh))
   m = Macaroon(
            location='',
            identifier='AXIEL_LAUNCH_TOKEN',
            key='bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0=',
            version=MACAROON_V1
        )
   print(m.identifier)
   print('-----------------------------------')
   print(m.serialize())
   print(AXIEL.state)
   print('-----------------------------------')
   pub = AXIEL.session_pub
   if not AXIEL.logged_in:
       pub = AXIEL.new_session()
       
   AXIEL.logo_url = url_for('static', filename='hvym_logo.png')
   template = AXIEL.view_template
   components=_load_components(AXIEL.view_components)
   page = AXIEL.active_page
   js=_load_js(AXIEL.view_components)
   logo=AXIEL.logo_url
   shared_dialogs=_load_components(AXIEL.shared_dialogs)
   shared_dialogs_js=_load_js(AXIEL.shared_dialogs)
   client_tokens= _load_js('macaroons_js_bundle')
   
   session_data = { 'pub': pub, 'generator_pub': AXIEL.node_pub, 'time': AXIEL.session_ends, 'nonce': AXIEL.session_nonce }
   return render_template(template, page=page, components=components, js=js, logo=logo, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js, client_tokens=client_tokens, session_data=session_data)

@app.route('/end_session', methods=['POST'])
def end_session():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_request(data['client_pub'], data['token']):  # client must send valid launch token
        raise Unauthorized()  # Unauthorized

   else:
        AXIEL.end_session()
        
        return jsonify({'authorized': False}), 200

@app.route('/new_node', methods=['POST'])
def new_node():
   required = ['token', 'client_pub', 'launch_token', 'seed_cipher', 'generator_pub']
   data = request.get_json()

   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.state == 'initialized':  # AXIEL must be initialized
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_request(data['client_pub'], data['token']) or not AXIEL.verify_launch(data['launch_token']):  # client must send valid launch token
        raise Unauthorized()  # Unauthorized

   else:
        AXIEL.new_node()
        AXIEL.set_client_session_pub(data['client_pub'])
        AXIEL.set_seed_cipher(data['seed_cipher'])
        AXIEL.set_client_node_pub(data['generator_pub'])
        AXIEL.new()
        
        return AXIEL.establish_data(), 200


@app.route('/establish', methods=['POST'])
def establish():
   required = ['token', 'client_pub', 'name', 'descriptor', 'meta_data']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.state == 'establishing':  # AXIEL must be establishing
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_request(data['client_pub'], data['token']):  # client must send valid session token
        raise Unauthorized()  # Unauthorized

   else:
        AXIEL.set_node_data(data['name'], data['descriptor'], data['meta_data'])
        AXIEL.established()
        
        return AXIEL.establish_data(), 200
   

@app.route('/authorize', methods=['POST'])
def authorize():
   required = ['token', 'client_pub', 'auth_token', 'generator_pub']
   data = request.get_json()

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif AXIEL.session_active or not AXIEL.state == 'idle':  # AXIEL must be idle
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.token_not_expired(data['client_pub'], data['token']) or not AXIEL.verify_request(data['client_pub'], data['token']) or not AXIEL.verify_generator(data['generator_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        AXIEL.set_client_session_pub(data['client_pub'])
        AXIEL.authorized()
        return jsonify({'name': AXIEL.node_name, 'descriptor': AXIEL.node_descriptor, 'logo': AXIEL.logo_url, 'nonce': AXIEL.auth_nonce, 'expires': str(AXIEL.session_ends), 'authorized': True}), 200
   

@app.route('/authorized', methods=['POST'])
def authorized():
   required = ['token', 'auth_token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.token_not_expired(data['client_pub'], data['token']) and not AXIEL.session_active or not AXIEL.state == 'idle':  # AXIEL must be idle
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_authorization(data['client_pub'], data['auth_token']):  # client must send valid tokens
        raise Unauthorized()  # Unauthorized
   else:
        return jsonify({'name': AXIEL.node_name, 'descriptor': AXIEL.node_descriptor, 'logo': AXIEL.logo_url, 'nonce': AXIEL.auth_nonce, 'expires': str(AXIEL.session_ends), 'authorized': True}), 200
   

@app.route('/deauthorize', methods=['POST'])
def deauthorize():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.session_active:  # Session must be active
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_request(data['client_pub'], data['token']):  # client must send valid launch token
        raise Unauthorized()  # Unauthorized

   else:
        AXIEL.deauthorized()
        AXIEL.end_session()
        
        return jsonify({'authorized': False}), 200



@app.route('/data', methods=['POST'])
def create_data():
   data = request.get_json()
   # Here you would normally save the data to a database
   return jsonify(message='Data received', data=data), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)