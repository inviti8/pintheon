import os
from flask import Flask, render_template, request, session, abort, redirect, jsonify, url_for
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound
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

AXIEL = AxielMachine(STATIC_PATH, DB_PATH, WALLET_PATH)
AXIEL.initialize()

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
   template = AXIEL.view_template
   components=_load_components(AXIEL.view_components)
   js=_load_js(AXIEL.view_components)
   logo=AXIEL.logo_url
   shared_dialogs=_load_components(AXIEL.shared_dialogs)
   shared_dialogs_js=_load_js(AXIEL.shared_dialogs)
   client_tokens= _load_js('macaroons_js_bundle')
   session_pub = AXIEL.new_session()
   print(session_pub)
   return render_template(template, components=components, js=js, logo=logo, shared_dialogs=shared_dialogs, shared_dialogs_js=shared_dialogs_js, client_tokens=client_tokens, session_pub=session_pub)
   #return jsonify(message='||AXIEL||')

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
def establishing():
   required = ['token', 'client_pub']
   data = request.get_json()
   print(data)

   if not _payload_valid(required, data):
        abort(400)  # Bad Request

   elif not AXIEL.state == 'establishing':  # AXIEL must be establishing
        abort(Forbidden())  # Forbidden
    
   elif not AXIEL.verify_request(data['client_pub'], data['token']):  # client must send valid launch token
        raise Unauthorized()  # Unauthorized

   else:
        AXIEL.established()
        
        return AXIEL.establish_data(), 200



@app.route('/data', methods=['POST'])
def create_data():
   data = request.get_json()
   # Here you would normally save the data to a database
   return jsonify(message='Data received', data=data), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)