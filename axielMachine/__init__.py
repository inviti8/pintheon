"""Finite state machine for node."""

__version__ = "0.01"
import os
import json
import base64
from base64 import b64encode, b64decode
import requests
import subprocess
from transitions import Machine, State
from cryptography.fernet import Fernet 
from tinydb import TinyDB
import tinydb_encrypted_jsonstorage as tae
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from Crypto.PublicKey import ECC
from pymacaroons import Macaroon, Verifier


class AxielMachine(object):

    states = ['spawned', 'initialized', 'establishing', 'idle', 'handling_file', 'redeeming']

    def __init__(self, static_path, db_path, wallet_path, xelis_daemon='https://node.xelis.io/json_rpc', ipfs_daemon='http://127.0.0.1:5001', xelis_network="Mainnet"):

        #self.key = base64.b64encode(Fernet.generate_key()).decode('utf-8')
        self.key = 'bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0='##DEBUG
        self.static_path = static_path
        self.db_path = db_path
        self.db = None
        self.node_data = None
        self.wallet_path = wallet_path
        self.xelis_daemon = xelis_daemon
        self.ipfs_daemon = ipfs_daemon
        self.xelis_network = xelis_network
        self.logo_url = None
        self.node_name = None
        self.node_descriptor = None
        self.view_template = 'index.html'
        self.view_components = 'new_node'
        self.shared_dialogs = 'shared_dialogs'
        self.session_priv = None
        self.session_pub = None

        # Initialize the state machine
        self.machine = Machine(model=self, states=AxielMachine.states, initial='spawned')

        self.machine.add_transition(trigger='initialize', source='spawned', dest='initialized', conditions=['do_initialize'])

        self.machine.add_transition(trigger='establish', source='initialized', dest='establishing', conditions=['do_establish'])

        self.machine.add_transition(trigger='established', source='establishing', dest='idle', conditions=['on_established'])

        self.machine.add_transition(trigger='handle_file', source='idle', dest='handling_file', conditions=['do_handle_file'])

        self.machine.add_transition(trigger='handled_file', source='handling_file', dest='idle', conditions=['on_file_handled'])

        self.machine.add_transition(trigger='redeem', source='idle', dest='redeeming', conditions=['do_redeem'])

        self.machine.add_transition(trigger='redeemed', source='redeeming', dest='idle', conditions=['on_redeemed'])

        self._initialize_db()

    def ab2hexstring(b):
        return ''.join('{:02x}'.format(c) for c in b)
    
    def new_session(self):
        self.session_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bytes = self.session_priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.session_pub = bytes.decode('utf-8').replace('\n', '\\n')
        return self.session_pub
    
    def generate_shared_secret(self, pem_string):
        pub_key = serialization.load_pem_public_key(pem_string.encode('utf-8'), default_backend())
        shared_secret = self.session_priv.exchange(ec.ECDH(), pub_key)
        return base64.b64encode(shared_secret).decode('utf-8')
    

    def pem_format(self, base64_string, type='PUBLIC KEY'):
        header = f"-----BEGIN {type}-----"
        footer = f"-----END {type}-----"
        
        # Split the base64 string into 64-character chunks except for the last one
        lines = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
        
        return "\n".join([header] + lines + [footer])

    @property
    def do_initialize(self):
        print('initializing!!')
        self._update_node_data(os.path.join(self.static_path, 'hvym_logo.png'), 'AXIEL', 'XRO Network')
        return True
    
    @property
    def do_wait(self):
        print('waiting!!')

    @property
    def do_establish(self):
        print('establishing!!')
        
    @property
    def on_established(self):
        print('established!!')

    def do_redeem(self):
        print('redeem')

    def on_redeemed(self):
        print('redeemed')

    @property
    def do_handle_file(self):
        print('handle file!!')
            
    @property
    def on_file_handled(self):
        print('file handled!!')

    def _update_node_data(self, logo_url, name, descriptor):
        self._open_db()
        self.logo_url = logo_url
        self.node_name = name
        self.node_descriptor = descriptor

        self.node_data.insert({ 'logo_url':self.logo_url, 'node_name':self.node_name, 'node_descriptor':self.node_descriptor })
        self.db.close()

    def _initialize_db(self):
        print('INITIALIZE DB!!')
        self._open_db()
        self.db.close()

    def _open_db(self):
        self.db = TinyDB(encryption_key=self.key, path=self.db_path, storage=tae.EncryptedJSONStorage)
        self.node_data = self.db.table('node_data')

    def _wallet_config(self, outPath):
        wallet_config = {
                "rpc": {
                    "rpc_bind_address": None,
                    "rpc_username": None,
                    "rpc_password": None,
                    "rpc_threads": None
                },
                "network_handler": {
                    "daemon_address": f"{self.xelis_daemon}",
                    "offline_mode": False
                },
                "precomputed_tables": {
                    "precomputed_tables_l1": 26,
                    "precomputed_tables_path": None
                },
                "log": {
                    "log_level": "info",
                    "file_log_level": None,
                    "disable_file_logging": False,
                    "disable_file_log_date_based": False,
                    "disable_log_color": False,
                    "disable_interactive_mode": False,
                    "filename_log": "xelis-wallet.log",
                    "logs_path": "logs/",
                    "logs_modules": []
                },
                "wallet_path": f"{self.wallet_path}",
                "password": None,
                "seed": "null",
                "network": f"{self.xelis_network}",
                "enable_xswd": False,
                "disable_history_scan": False,
                "force_stable_balance": False
            }
        with open(os.path.join(outPath, 'wallet_config.json'), 'w') as f:
            json.dump(wallet_config, f)

    def _open_wallet(self):
        print('open wallet')

    def _add_file_to_ipfs(file_name, file_data):
        url = f'{self.ipfs_endpoint}/api/v0/add'

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
            # cid = pin_cid_to_ipfs(ipfs_data['Hash'])
        else:
            return None