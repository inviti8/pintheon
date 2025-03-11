"""Finite state machine for node."""

__version__ = "0.01"
import os
import uuid
import json
import base64
from base64 import b64encode, b64decode
import requests
import subprocess
from transitions import Machine, State
from cryptography.fernet import Fernet, InvalidToken
from tinydb import TinyDB
import tinydb_encrypted_jsonstorage as tae
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pymacaroons import Macaroon, Verifier
import hashlib
import hashlib, binascii
import datetime
from datetime import timedelta
from platformdirs import *


class AxielMachine(object):

    states = ['spawned', 'initialized', 'establishing', 'idle', 'handling_file', 'redeeming']

    def __init__(self, static_path, db_path, wallet_path, xelis_daemon='https://node.xelis.io/json_rpc', ipfs_daemon='http://127.0.0.1:5001', xelis_network="Mainnet"):

        self.uid = str(uuid.uuid4())
        self.launch_token = 'MDAwZWxvY2F0aW9uIAowMDIyaWRlbnRpZmllciBBWElFTF9MQVVOQ0hfVE9LRU4KMDAyZnNpZ25hdHVyZSB7MtcrDXWZNrLHqD5rVyOduvQKQ7EF2GaOEwW5phJUbAo'
        #self.master_key = base64.b64encode(Fernet.generate_key()).decode('utf-8')
        self.session_active = False
        self.session_started = None
        self.session_ends = None
        self.session_nonce = None
        self.session_hours = 1
        self.root_token = None
        self.master_key = 'bnhvRDlzdXFxTm9MMlVPZDZIbXZOMm9IZmFBWEJBb29FemZ4ZU9zT1p6Zz0='##DEBUG
        self.static_path = static_path
        self.logo_url = None
        self.node_name = None
        self.node_descriptor = None
        self.node_meta_data = None

        #-------DB--------
        self.db_path = db_path
        self.db = None
        self.state_data = None
        self.xelis_config = None
        self.node_data = None

        #-------XELIS--------
        self.wallet_path = wallet_path
        self.xelis_daemon = xelis_daemon
        self.xelis_wallet_rpc = 'http://127.0.0.1:8081'
        self.xelis_network = xelis_network

        #-------IPFS--------
        self.ipfs_daemon = ipfs_daemon

        #-------VIEWS--------
        self.view_template = 'index.html'
        self.view_components = 'new_node'
        self.shared_dialogs = 'shared_dialogs'

        #-------KEYS--------
        self.session_priv = None
        self.session_pub = None
        self.node_priv = None
        self.node_pub = None

         #-------PRIVATE VARS--------
        self._generator_token = None
        self._BLOCK_SIZE = 16

        self._client_node_pub = None
        self._client_session_pub = None
        self._client_generator_pub = None
        self._seed_cipher = None

        self._dirs = PlatformDirs('AXIEL', 'XRO Network', ensure_exists=True)
        self._xelis_dirs = PlatformDirs('Xelis-Blockchain', 'Xelis Network', ensure_exists=True)
        self._xelis_wallet_path = os.path.join(self._dirs.user_config_dir,'xelis_wallet_config.json')

        # Initialize the state machine
        self.machine = Machine(model=self, states=AxielMachine.states, initial='spawned')

        self.machine.add_transition(trigger='initialize', source='spawned', dest='initialized', conditions=['do_initialize'])

        self.machine.add_transition(trigger='new', source='initialized', dest='establishing', conditions=['create_new_node'])

        self.machine.add_transition(trigger='established', source='establishing', dest='idle', conditions=['on_established'])

        self.machine.add_transition(trigger='handle_file', source='idle', dest='handling_file', conditions=['do_handle_file'])

        self.machine.add_transition(trigger='handled_file', source='handling_file', dest='idle', conditions=['on_file_handled'])

        self.machine.add_transition(trigger='redeem', source='idle', dest='redeeming', conditions=['do_redeem'])

        self.machine.add_transition(trigger='redeemed', source='redeeming', dest='idle', conditions=['on_redeemed'])

        self._initialize_db()
        print('@@@@@@@@@@@@')
        print(self._dirs.user_data_dir)
        print(self._dirs.user_config_dir)
        print(self._xelis_wallet_path)

    def set_client_node_pub(self, client_pub):
        self._client_node_pub = client_pub

    def get_client_node_pub(self):
        return self._client_node_pub

    def set_client_session_pub(self, client_pub):
        self.session_active = True
        self._client_session_pub = client_pub

    def get_client_session_pub(self):
        return self._client_session_pub
    
    def set_seed_cipher(self, seedCipher):
        self._seed_cipher = seedCipher

    def set_node_data(self, name, descriptor, metadata):
        self.node_name = name
        self.node_descriptor = descriptor
        self.node_meta_data = metadata

    def ab2hexstring(b):
        return ''.join('{:02x}'.format(c) for c in b)
    
    def check_time(self, caveat):
        if not caveat.startswith('time < '):
            return False
        try:
            now = datetime.datetime.now()
            when = datetime.datetime.strptime(caveat[7:], '%Y-%m-%d %H:%M:%S.%f')

            if str(when) != str(self.session_ends):
                return False
            else:
                return now < when
        except:
            return False
                
    def token_not_expired(self, b64_pub, client_token):
        v = Verifier()
        client_mac = Macaroon.deserialize(client_token)
        v.satisfy_general(self.check_time)

        return v.verify(client_mac, self.generate_shared_session_secret(b64_pub))
    
    def verify_request(self, b64_pub, client_token):
        result = False

        client_mac = Macaroon.deserialize(client_token)
        mac = Macaroon(
            location=client_mac.location,
            identifier='AXIEL_SESSION',
            key=self.generate_shared_session_secret(b64_pub)
        )

        mac.add_first_party_caveat('time < '+ str(self.session_ends))
        
        if mac.signature == client_mac.signature:
            result = True
        
        return result
    
    def verify_launch(self, client_launch_token):
        result = False
        server_mac = Macaroon.deserialize(self.launch_token)
        client_mac = Macaroon.deserialize(client_launch_token)

        if server_mac.signature == client_mac.signature:
            result = True
        
        return result
    
    def verify_generator(self, client_generator_pub, client_root_token):
        result = False
        server_mac = Macaroon.deserialize(self.root_token)
        client_mac = Macaroon.deserialize(client_root_token)

        server_mac.add_first_party_caveat('nonce == '+self.session_nonce)

        if client_generator_pub == self._client_node_pub and server_mac.signature == client_mac.signature:
            result = True
        
        return result
    
    def hash_key(self, key):
        return hashlib.sha256(key.encode('utf-8')).hexdigest()
    
    def pad_key(self, key):
        key_bytes = key.encode('utf-8')
        if len(key_bytes) > 32:
            return key_bytes[:32]  # Trim if the key is too long
        elif len(key_bytes) < 32:
            return key_bytes.ljust(32, b'\0')  # Pad with null bytes if too short
        return key_bytes
    
    def new_session(self):
        keypair = self._new_keypair()
        self.session_priv = keypair['priv']
        self.session_pub = keypair['pub']
        self.session_started = datetime.datetime.now()
        self.session_ends = self.session_started + timedelta(hours=self.session_hours)
        self.session_nonce = str(uuid.uuid4())
        return self.session_pub
    
    def end_session(self):
        self.session_active = False
        self._client_session_pub = None
        self.session_started = None
        self.session_ends = None
        self.session_nonce = None
    
    def new_node(self):
        keypair = self._new_keypair()
        self.node_priv = keypair['priv']
        self.node_pub = keypair['pub']
        return self.session_pub
    
    def generate_shared_session_secret(self, b64_pub):
        return self._create_shared_secret(b64_pub, self.session_priv)

    def generate_shared_node_secret(self):
        return self._create_shared_secret(self._client_node_pub, self.node_priv)

    def pem_format(self, base64_string, type='PUBLIC KEY'):
        header = f"-----BEGIN {type}-----"
        footer = f"-----END {type}-----"

        lines = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
        
        return "\n".join([header] + lines + [footer])
        
    def derive_key(self, password, salt):
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), binascii.unhexlify(salt), 100000)
        return dk
    
    def decrypt_aes(self, data, key):
        padded = self.pad_key(key)

        data = base64.b64decode(data.encode('utf-8'))

        iv = data[:self._BLOCK_SIZE]
        encrypted_data = data[self._BLOCK_SIZE:]

        cipher = AES.new(padded, AES.MODE_CBC, iv)

        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = decrypted_data.rstrip(b'\0')
        unpadded_data = unpad(unpadded_data, AES.block_size)
        decrypted_data = unpadded_data.decode('utf-8')
        arr = decrypted_data.split('"')

        return arr[1]
    
    def establish_data(self):
        return {'node_id': self.uid, 'node_pub': self.node_pub, 'root_token': self.root_token, 'master_key': self.master_key}
    
    def _create_shared_secret(self, b64_pub, server_priv):
        pem_string = self.pem_format(b64_pub)
        pub_key = serialization.load_pem_public_key(pem_string.encode('utf-8'), default_backend())
        shared_secret = server_priv.exchange(ec.ECDH(), pub_key)
        return base64.b64encode(shared_secret).decode('utf-8')
    
    def _create_root_token(self):
        self.root_token = Macaroon(
            location='',
            identifier='AXIEL_GENERATOR',
            key=self.generate_shared_node_secret()
        ).serialize()

    def _create_generator_token(self):
        server_token = Macaroon.deserialize(self.root_token)
        server_token.add_third_party_caveat('', self.root_token, 'AXIEL_GENERATOR_TOKEN')
        return server_token

    @property
    def do_initialize(self):
        self._update_node_data(os.path.join(self.static_path, 'hvym_logo.png'), self._dirs.appname, self._dirs.appauthor)
        self._update_state_data()
        return True

    @property
    def create_new_node(self):
        print('creating new node...')
        self._wallet_config_gen()
        self._save_wallet_config()
        self._create_root_token()
        self._update_state_data()
        return True
        
    @property
    def on_established(self):
        print('established!!')
        self.view_components = 'dashboard'
        self._update_state_data()
        return True

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

    def _new_keypair(self):
        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bytes = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pub = bytes.decode('utf-8').replace('\n', '\\n')
        
        return { 'pub': pub, 'priv': priv }
    
    def _update_state_data(self):
        self._open_db()
        data = { 'current_state':str(self.state) }
        self._update_table_doc(self.state_data, data)
        self.db.close()

    def _update_node_data(self, logo_url, name, descriptor):
        self._open_db()
        self.logo_url = logo_url
        self.node_name = name
        data = { 'id':self.uid, 'node_name':self.node_name, 'logo_url':self.logo_url, 'node_descriptor':self.node_descriptor, 'master_key':self.master_key, 'launch_token': self.launch_token, 'root_token': self.root_token }
        
        self._update_table_doc(self.node_data, data)

        print(self.node_data.all())

        self.db.close()

    def _initialize_db(self):
        self._open_db()
        self.db.close()

    def _update_table_doc(self, table, data, id=1):
        if not table.contains(doc_id=id):
            table.insert(data)
        else:
            table.get(doc_id=id).update(data)

    def _open_db(self):
        self.db = TinyDB(encryption_key=self.master_key, path=self.db_path, storage=tae.EncryptedJSONStorage)
        self.state_data = self.db.table('state_data')
        self.node_data = self.db.table('node_data')
        self.xelis_config = self.db.table('xelis_config')

    def _xelis_wallet_rpc_auth(username, password):
        auth = f"{username}:{password}"
        encoded_auth = base64.b64encode(auth.encode('utf-8')).decode('utf-8')
        return encoded_auth

    def _wallet_config_gen(self):

        seed = self.decrypt_aes(self._seed_cipher, self.generate_shared_session_secret(self._client_session_pub))

        wallet_config = {
                "rpc": {
                    "rpc_bind_address": f'{self.xelis_wallet_rpc}',
                    "rpc_username": f'{self.uid}',
                    "rpc_password": f'{self.master_key}',
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
                "password": f"{self.master_key}",
                "seed": seed,
                "network": f"{self.xelis_network}",
                "enable_xswd": False,
                "disable_history_scan": False,
                "force_stable_balance": False
            }
        
        self._open_db()

        self._update_table_doc(self.xelis_config, wallet_config)

        self.db.close()

    def _save_wallet_config(self):
        print('save wallet config')
        self._open_db()
        wallet_config = self.xelis_config.get(doc_id=1)
        with open(self._xelis_wallet_path, 'w') as f:
            json.dump(wallet_config, f)

        self.db.close()

    def _open_wallet(self):
        print('open wallet')

    def _add_file_to_ipfs(self, file_name, file_data):
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