"""Finite state machine for node."""

__version__ = "0.01"
import os
import uuid
import json
import base64
import subprocess
from base64 import b64encode, b64decode
from flask import jsonify
import requests
import subprocess
from transitions import Machine, State
from cryptography.fernet import Fernet, InvalidToken
from tinydb import TinyDB, Query
import tinydb_encrypted_jsonstorage as tae
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from stellar_sdk import Keypair
from pymacaroons import Macaroon, Verifier
import hashlib
import hashlib, binascii
import datetime
from datetime import timedelta
from platformdirs import *
import re
import tempfile
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import SolidFillColorMask
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from PIL import Image, ImageDraw
from stellar_sdk import Keypair, Network, Server, TransactionBuilder

HVYM_BG_RGB = (152, 49, 74)
HVYM_FG_RGB = (175, 232, 197)
STELLAR_BG_RGB = (0, 0, 0)
STELLAR_FG_RGB = (21, 21, 21)


class PhilosMachine(object):

    states = ['spawned', 'initialized', 'establishing', 'idle', 'handling_file', 'redeeming']

    def __init__(self, static_path, db_path, wallet_path, ipfs_daemon='http://127.0.0.1:5001'):

        self.uid = str(uuid.uuid4())
        self.launch_token = 'MDAwZWxvY2F0aW9uIAowMDIyaWRlbnRpZmllciBBWElFTF9MQVVOQ0hfVE9LRU4KMDAyZnNpZ25hdHVyZSB7MtcrDXWZNrLHqD5rVyOduvQKQ7EF2GaOEwW5phJUbAo'
        #self.master_key = base64.b64encode(Fernet.generate_key()).decode('utf-8')
        self.session_active = False
        self.session_started = None
        self.session_ends = None
        self.session_nonce = None
        self.session_hours = 1
        self.auth_nonce = None
        self.auth_token = None
        self.logged_in = False
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
        self.node_data = None
        self.file_book = None
        self.peer_book = None
        self.stellar_book = None
        self.namespaces = None

        #-------IPFS--------
        self.ipfs_daemon = ipfs_daemon
        self.ipfs_endpoint = 'http://127.0.0.1:5001/api/v0'

        #-------VIEWS--------
        self.view_template = 'index.html'
        self.view_components = 'new_node'
        self.active_page = 'new_node'
        self.shared_dialogs = 'shared_dialogs'

        #-------KEYS--------
        self.session_priv = None
        self.session_pub = None
        self.node_priv = None
        self.node_pub = None

        #-------STELLAR--------
        self.stellar_server = Server("https://horizon-testnet.stellar.org")
        self.stellar_account = None
        self.stellar_keypair = None

         #-------PRIVATE VARS--------
        self._generator_token = None
        self._BLOCK_SIZE = 16

        self._client_node_pub = None
        self._client_session_pub = None
        self._client_generator_pub = None
        self._seed_cipher = None

        self._dirs = PlatformDirs('PHILOS', 'XRO Network', ensure_exists=True)

        # Initialize the state machine
        self.machine = Machine(model=self, states=PhilosMachine.states, initial='spawned')

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
        result = True
        if not caveat.startswith('time < '):
            try:
                now = datetime.datetime.now()
                when = datetime.datetime.strptime(caveat[7:], '%Y-%m-%d %H:%M:%S.%f')

                result = now < when
            
            except:
                result = False
        
        return result
                
    def token_not_expired(self, b64_pub, client_token):
        v = Verifier()
        client_mac = Macaroon.deserialize(client_token)
        client_mac.inspect()
        v.satisfy_general(self.check_time)

        return v.verify(client_mac, self.generate_shared_session_secret(b64_pub))
    
    def verify_request(self, b64_pub, client_token):
        result = False

        client_mac = Macaroon.deserialize(client_token)
        mac = Macaroon(
            location=client_mac.location,
            identifier='PHILOS_SESSION',
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
    
    def verify_authorization(self, b64_pub, client_token):
        result = False

        client_mac = Macaroon.deserialize(client_token)

        mac = Macaroon(
            location=client_mac.location,
            identifier=client_mac.identifier,
            key=self.generate_shared_session_secret(b64_pub)
        )
        mac.add_first_party_caveat('nonce == '+self.auth_nonce)
        mac.add_first_party_caveat('time < '+ str(self.session_ends))

        if mac.signature == client_mac.signature:
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
        self.logged_in = False
        self._client_session_pub = None
        self.session_started = None
        self.session_ends = None
        self.session_nonce = None

    def authorized(self):
        self.auth_nonce = str(uuid.uuid4())
        self.auth_token = self._create_auth_token()
        self.logged_in = True
        self.session_active = True
        self.active_page = 'dashboard'

    def deauthorized(self):
        self.auth_nonce = None
        self.auth_token = None
        self.logged_in = False
        self.session_active = False
        self.active_page = 'authorize'
    
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
    
    def _custom_qr_code(data, cntrImg, back_color=HVYM_BG_RGB, front_color=HVYM_FG_RGB):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(image_factory=StyledPilImage, 
            module_drawer=RoundedModuleDrawer(),
            color_mask=SolidFillColorMask(back_color=back_color, front_color=front_color),
            embeded_image_path=cntrImg)
        qr = None
        with tempfile.NamedTemporaryFile(suffix='.png', delete=True) as f:
            img.save(f, format='PNG') 
            qr = f

        return qr
    
    def _create_shared_secret(self, b64_pub, server_priv):
        pem_string = self.pem_format(b64_pub)
        pub_key = serialization.load_pem_public_key(pem_string.encode('utf-8'), default_backend())
        shared_secret = server_priv.exchange(ec.ECDH(), pub_key)
        return base64.b64encode(shared_secret).decode('utf-8')
    
    def _create_root_token(self):
        self.root_token = Macaroon(
            location='',
            identifier='PHILOS_GENERATOR',
            key=self.generate_shared_node_secret()
        ).serialize()

    def _create_auth_token(self):
        mac = Macaroon(
            location='',
            identifier='PHILOS_AUTH',
            key=self.generate_shared_session_secret(self._client_session_pub)
        )
        mac.add_first_party_caveat('nonce == '+self.auth_nonce)
        mac.add_first_party_caveat('time < '+ str(self.session_ends))

        self.auth_token  = mac.serialize()

    def _create_stellar_keypair_from_seed(self, seed):
         print('create stellar keypair')
         self.stellar_keypair = Keypair.from_mnemonic_phrase(seed)

         keypair = { 'pub': self.stellar_keypair.public_key, 'priv': self.stellar_keypair.secret }
         self._open_db()
         self.stellar_book.insert(keypair)
         self.db.close()
         
         self.stellar_account = self.stellar_server.accounts().account_id(self.stellar_keypair.public_key).call()
         for balance in self.stellar_account['balances']:
            print(f"Type: {balance['asset_type']}, Balance: {balance['balance']}")

    @property
    def do_initialize(self):
        self._update_node_data(os.path.join(self.static_path, 'hvym_logo.png'), self._dirs.appname, self._dirs.appauthor)
        self._update_state_data()
        return True

    @property
    def create_new_node(self):
        print('creating new node...')
        seed = self.decrypt_aes(self._seed_cipher, self.generate_shared_session_secret(self._client_session_pub))
        self._create_stellar_keypair_from_seed(seed)
        self._create_root_token()
        self._update_state_data()
        self.active_page = 'establish'
        self.logged_in = True
        return True
        
    @property
    def on_established(self):
        print('established!!')
        self.view_components = 'dashboard'
        self.active_page = 'authorize'
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
        self.node_descriptor = descriptor
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
        self.file_book= self.db.table('file_book')
        self.peer_book= self.db.table('peer_book')
        self.stellar_book= self.db.table('stellar_book')
        self.namespaces= self.db.table('namespaces')


    def _open_wallet(self):
        print('open wallet')

    def _safe_ipns_key(self, key):
        # Remove any characters that are not lowercase letters, digits or hyphens/periods
        key = re.sub('[^a-z0-9.-]', '', key)
        
        # If the string starts with a period or hyphen, remove it
        if key[0] in '-.':
            key = key[1:]
            
        # Truncate the string to max allowed length (253 - 1 for '.')
        return key[:253-1] + '.' if len(key) > 253 else key

    def get_stats(self, stat_type):
        url = f'{self.ipfs_endpoint}/stats/{stat_type}?'
        response = requests.post(url);

        #return requests.post(url)
        # print('stat res : ',response.json())
        # print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400
        
    def get_peer_id(self):
        url = f'{self.ipfs_endpoint}/config?arg=Identity.PeerID'
        response = requests.post(url);

        #return requests.post(url)
        # print(response)
        # print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400
        
    def pin_cid_to_ipfs(self, cid):
        # print('pin_cid_to_ipfs')
        pin_url = f'{self.ipfs_endpoint}/pin/add?arg={cid}'
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
        
    def remove_file_from_ipfs(self, cid):
        print('remove_file_from_ipfs')
        url = f'{self.ipfs_endpoint}/pin/rm?arg={cid}&recursive=true'
        print(url)
        response = requests.post(url)

        print(response.text)

        if response.status_code == 200:
                url = f'{self.ipfs_endpoint}/repo/gc'
                data = response.json()
                print(data)
                response = requests.post(url)
                if response.status_code == 200:
                    print(response)
                    print(response.text)
                    ipfs_data = response.text
                    print(ipfs_data)
                    self._open_db()
                    File = Query()
                    self.file_book.remove(File.CID == cid)
                    all_file_info = self.file_book.all()
                    self.db.close()

                    return all_file_info
                else:
                     return None
        else:
             return None
        
    def get_file_list(self):
        url = f'{self.ipfs_endpoint}/files/ls'
        response = requests.post(url);

        #return requests.post(url)
        print(response)
        print(response.text)
        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400
        
    def get_peer_list(self):
        url = f'{self.ipfs_endpoint}/bootstrap/list'
        response = requests.post(url);

        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400

    def add_file_to_ipfs(self, file_name, file_type, file_data):
        url = f'{self.ipfs_endpoint}/add'

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
            cid = self.pin_cid_to_ipfs(ipfs_data['Hash'])
            if cid != None:
                file_info = {'Name':ipfs_data['Name'], 'Type': file_type, 'Hash':ipfs_data['Hash'], 'CID':cid, 'Size':ipfs_data['Size']}
                self._open_db()
                self.file_book.insert(file_info)
                all_file_info = self.file_book.all()
                self.db.close()

                return all_file_info
        else:
            return None
        
    def add_cid_to_ipns(self, cid, name=None):
        url = f'{self.ipfs_endpoint}/name/publish?arg={cid}&key=self'
        if name != None:
            url = f'{self.ipfs_endpoint}/name/publish?arg={cid}&key={self._safe_ipns_key(name)}'
        response = requests.post(url)

        if response.status_code == 200:
            ipns_data = response.json()
            self._open_db()
            self.namespaces.insert(ipns_data)
            all_file_info = self.file_book.all()
            self.db.close()

            return all_file_info
        
        else:
            return None
        
    def resolve_ipns(self, name):
        url = f'{self.ipfs_endpoint}/name/resolve?arg={name}'
        response = requests.post(url)
        if response.status_code == 200:
            return response.json()
        else:
            return None
        
    def get_dashboard_data(self):
        result = {'moniker':None, 'peer-id':None, 'stats':None, 'files':None, 'peers':None}
        stats_response = self.get_stats('bw')
        files_list = self.file_book.all()
        peers_response = self.get_peer_list()
        peer_id_response = self.get_peer_id()


        if stats_response.status_code == 200:
                result['stats'] = stats_response.json()

        if files_list != None:
                result['files'] = files_list

        if peers_response.status_code == 200:
                result['peers'] = peers_response.json()['Peers']

        if peer_id_response.status_code == 200:
                result['peer-id'] = peer_id_response.json()['Value']

        return result