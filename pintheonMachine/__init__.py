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
from tinydb import *
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
import re
import tempfile
import qrcode
from qrcode.image.styledpil import StyledPilImage
from qrcode.image.styles.moduledrawers.pil import RoundedModuleDrawer
from qrcode.image.styles.colormasks import SolidFillColorMask
from qrcode.image.styles.colormasks import RadialGradiantColorMask
from PIL import Image, ImageDraw
from stellar_sdk import Keypair, Network, Server, SorobanServer, soroban_rpc, scval
from stellar_sdk import xdr as stellar_xdr
from .hvym_collective_bindings import Client as Collective
from .opus_bindings import Client as Opus
from .ipfs_token_bindings import Client as IPFS_Token
import json
import requests
import time
from hvym_stellar import *
import py7zr

HVYM_BG_RGB = (152, 49, 74)
HVYM_FG_RGB = (175, 232, 197)
OPUS_BG_RGB = (134, 10, 188)
OPUS_FG_RGB = (202, 132, 2)
STELLAR_BG_RGB = (255, 255, 255)
STELLAR_FG_RGB = (0, 0, 0)

XLM_TESTNET = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC'
COLLECTIVE_TESTNET = 'CC6T2LSDWVTZCDZBHEG22RPV4QL6C5KISLGAWWEDMMBXQ7AD6WYVGYRV'
OPUS_TESTNET = 'CANXZXYPQKNUD7VAPVW4B5ZTIDYPRDHW2CFKLNQA4ZYM4UKDZRQZWEXC'
XLM_MAINNET = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC'
COLLECTIVE_MAINNET = 'CC6T2LSDWVTZCDZBHEG22RPV4QL6C5KISLGAWWEDMMBXQ7AD6WYVGYRV'
OPUS_MAINNET = 'CANXZXYPQKNUD7VAPVW4B5ZTIDYPRDHW2CFKLNQA4ZYM4UKDZRQZWEXC'

DEBUG_SEED = "puppy address situate future gown trade limb rival crane increase when faculty category vague alpha program remember pill waste light broom decade buddy knock"
DEBUG_NODE_CONTRACT = "CBYP223JS7VYBIIFYUJ6ZQLAOOYXCIFZGMOHKIASMWKCZGFULVPNPV3H"
DEBUG_URL_HOST = 'http://127.0.0.1:5000'
FAKE_IPFS_HOST = 'https://sapphire-giant-butterfly-891.mypinata.cloud'
FAKE_IPFS_FILE1 = str(uuid.uuid4())
FAKE_IPFS_FILE2 = str(uuid.uuid4())
FAKE_IPFS_FILE3 = str(uuid.uuid4())
FAKE_IPFS_FILES = [FAKE_IPFS_FILE1, FAKE_IPFS_FILE2, FAKE_IPFS_FILE3]


class PintheonMachine(object):

    states = ['spawned', 'initialized', 'establishing', 'idle', 'handling_file', 'redeeming']

    def __init__(self, static_path, db_path, ipfs_daemon='http://127.0.0.1:5001', toml_gen = None, testnet = False, debug = False, fake_ipfs=True):

        self.uid = str(uuid.uuid4())
        self.version = "0.0.1"
        self.use_testnet = testnet
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
        self.is_established = False
        self.static_path = static_path
        self.logo_url = None
        self.node_contract = None
        self.node_name = None
        self.node_descriptor = None
        self.node_meta_data = None
        self.url_host = None

        #-------DB--------
        self.db_path = db_path
        self.db = None
        self.state_data = None
        self.node_data = None
        self.customization = None
        self.file_book = None
        self.peer_book = None
        self.stellar_book = None
        self.namespaces = None
        self.token_book = None
        self.access_tokens = None

        #-------IPFS--------
        # Use environment variable for IPFS path if available
        self.ipfs_path = os.environ.get('PINTHEON_IPFS_PATH', '/home/pintheon/data/ipfs')
        self.ipfs_daemon = ipfs_daemon
        self.ipfs_endpoint = self.ipfs_daemon+'/api/v0'

        #-------VIEWS--------
        self.view_template = 'admin.html'
        self.view_components = 'new_node'
        self.active_page = 'new_node'
        self.shared_dialogs = 'shared_dialogs'

        #--CUSTOMIZATION----
        self.theme = 0
        self.themes = ['default', 'dark', 'light']
        self.bg_img = None

        #-------KEYS--------
        self.session_priv = None
        self.session_pub = None
        self.node_priv = None
        self.node_pub = None

        #-------STELLAR--------
        self.block_explorer = "https://stellar.expert/explorer"
        self.testnet_transaction = "/testnet/tx/"
        self.mainnet_transaction = "/public/tx/"
        self.soroban_rpc_url = "https://soroban-testnet.stellar.org:443"
        self.stellar_server = Server("https://horizon-testnet.stellar.org")
        self.soroban_server = SorobanServer(self.soroban_rpc_url)
        self.stellar_initializing_keypair = Keypair.random()
        self.stellar_initializing_25519_keypair = Stellar25519KeyPair(self.stellar_initializing_keypair)
        self.XLM_REQUIRED_START_BALANCE = 100
        if self.use_testnet:
            self.XLM_ID = XLM_TESTNET
            self.COLLECTIVE_ID = COLLECTIVE_TESTNET
            self.OPUS_ID = OPUS_TESTNET
            self.NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
        else:
            self.XLM_ID = XLM_MAINNET
            self.COLLECTIVE_ID = COLLECTIVE_MAINNET
            self.OPUS_ID = OPUS_MAINNET
            self.NETWORK_PASSPHRASE = Network.PUBLIC_NETWORK_PASSPHRASE
        self.BASE_FEE = self.stellar_server.fetch_base_fee()
        self.stellar_account = None
        self.stellar_keypair = None
        self.stellar_25519_keypair = None
        self.hvym_collective = Collective(self.COLLECTIVE_ID, self.soroban_rpc_url, self.NETWORK_PASSPHRASE)
        self.opus = Opus(self.OPUS_ID, self.soroban_rpc_url, self.NETWORK_PASSPHRASE)
        self.stellar_logo_img = None
        self.stellar_wallet_qr = None
        self.stellar_logo_light = None
        self.stellar_logo_dark = None
        self.stellar_logo = None
        self.opus_logo = None
        self.boros_logo = None
        self.TOML_GEN = toml_gen
        self.stellar_toml = None
        
         #-------PRIVATE VARS--------
        self._generator_token = None
        self._BLOCK_SIZE = 16

        #--------DEBUG--------------
        self.DEBUG = debug
        self.FAKE_IPFS = fake_ipfs

        self._client_node_pub = None
        self._client_session_pub = None
        self._client_generator_pub = None
        self._seed_cipher = None

        # Use platformdirs for additional data storage if needed
        self._dirs = PlatformDirs('PINTHEON', 'XRO Network', ensure_exists=True)

        # Initialize the state machine
        self.machine = Machine(model=self, states=PintheonMachine.states, initial='spawned')

        self.machine.add_transition(trigger='initialize', source='spawned', dest='initialized', conditions=['do_initialize'])

        # Allow resume_state from any state to idle
        self.machine.add_transition(trigger='resume_state', source='*', dest='idle', conditions=['on_resume_state'])

        self.machine.add_transition(trigger='new', source='initialized', dest='establishing', conditions=['create_new_node'])

        self.machine.add_transition(trigger='init_reset', source='establishing', dest='initialized', conditions=['reset_init'])

        self.machine.add_transition(trigger='established', source='establishing', dest='idle', conditions=['on_established'], after=['activated'])

        self.machine.add_transition(trigger='handle_file', source='idle', dest='handling_file', conditions=['do_handle_file'])

        self.machine.add_transition(trigger='handled_file', source='handling_file', dest='idle', conditions=['on_file_handled'])

        self.machine.add_transition(trigger='redeem', source='idle', dest='redeeming', conditions=['do_redeem'])

        self.machine.add_transition(trigger='redeemed', source='redeeming', dest='idle', conditions=['on_redeemed'])

        self._initialize_db()
        print('@@@@@@@@@@@@----------------------------------------------------------------')
        print(self.uid)
        print(f"Data Directory: {os.environ.get('PINTHEON_DATA_DIR', '/home/pintheon/data')}")
        print(f"IPFS Path: {self.ipfs_path}")
        print(f"DB Path: {self.db_path}")
        print(self._dirs.user_data_dir)
        print(self._dirs.user_config_dir)
        print(self._get_saved_state())
        print('@@@@@@@@@@@@----------------------------------------------------------------')
        if self._get_saved_established_state():
            self.resume_state()

    def soroban_online(self):
        result = None
        try:
            ledger = self.soroban_server.get_latest_ledger()
            result = "Soroban Online, "+str(ledger.sequence)
        except Exception as e:
            result = "Can't connect to Soroban: "+str(e)
        return result
    
    def set_client_node_pub(self, client_pub):
        self._client_node_pub = client_pub
        self._open_db()
        token = Query()
        self.node_keys.update({'client_pub': self._client_node_pub}, token.id == 'NODE_KEYS')
        self.db.close()

    def get_client_node_pub(self):
        return self._client_node_pub

    def set_client_session_pub(self, client_pub):
        self.session_active = True
        self._client_session_pub = client_pub

    def get_client_session_pub(self):
        return self._client_session_pub
    
    def set_seed_cipher(self, seedCipher):
        self._seed_cipher = seedCipher

    def set_node_data(self, name, descriptor, metadata, host):
        self.node_name = name
        self.node_descriptor = descriptor
        self.node_meta_data = metadata
        self.url_host = host

        if self.FAKE_IPFS:
            self.url_host = FAKE_IPFS_HOST

        if self.DEBUG:
            self.node_contract = DEBUG_NODE_CONTRACT
            self.url_host = DEBUG_URL_HOST
        else:
            self.join_collective()
            self.node_contract = self.deploy_node_token(name, descriptor)

        self.stellar_toml = self.TOML_GEN( file_path=self.static_path, org_name=self.node_name, org_dba='Pintheon Node', org_url=self.url_host, org_official_email='hi@pintheon.com', org_support_email='support@pintheon.com', org_twitter='@pintheon', org_description=self.node_descriptor, version=self.version, network_passphrase=self.NETWORK_PASSPHRASE, accounts=[self.stellar_keypair.public_key])

        self._update_node_data(self.logo_url, self.node_name, self.node_descriptor, self.node_contract)

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

        if self.DEBUG:
            result = True
        else:
            client_mac = Macaroon.deserialize(client_token)
            mac = Macaroon(
                location=client_mac.location,
                identifier='PINTHEON_SESSION',
                key=self.generate_shared_session_secret(b64_pub)
            )

            mac.add_first_party_caveat('time < '+ str(self.session_ends))
            
            if mac.signature == client_mac.signature:
                result = True
        
        return result
    
    def launch_token_valid(self, launch_token):
        verifier = StellarSharedKeyTokenVerifier(self.stellar_25519_keypair, launch_token)
        return verifier.valid()

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
        if self.stellar_keypair == None:
             self._load_stellar_keypair()

        self.auth_nonce = str(uuid.uuid4())
        self.auth_token = self._create_auth_token()
        self.logged_in = True
        self.session_active = True
        self.active_page = 'dashboard'

    def deauthorized(self):
        self.auth_nonce = None
        self.auth_token = None
        self.stellar_account = None
        self.stellar_keypair = None
        self.logged_in = False
        self.session_active = False
        self.active_page = 'authorize'
    
    def new_node(self):
        keypair = self._new_keypair()
        self.node_priv = keypair['priv']
        self.node_pub = keypair['pub']
        data = {'id': 'NODE_KEYS', 'pub': self.node_pub, 'priv' : self.serialize_private_key(self.node_priv), 'client_pub': None, 'root_token' : None}
        self._open_db()
        self._update_table_doc(self.node_keys, data)
        self.db.close()
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
    
    def token_send(self, token_id, recieving_address, amount):
         token = Opus(token_id, self.soroban_rpc_url, self.NETWORK_PASSPHRASE)
         tx = self._token_send(token, recieving_address, amount, token_id)
         current_balance = self._token_balance(token)
         if current_balance != None:
            self._update_token_book_balance(self.OPUS_ID, current_balance)

         return tx
    
    def opus_symbol(self):
        return self._token_symbol(self.opus)

    def opus_balance(self):
        raw = self._token_balance(self.opus)
        if raw is not None:
            return self.stroops_to_xlm(raw)
        return 0
    
    def update_opus_balance(self):
        balance = self.opus_balance()
        if balance != None:
            self._update_token_book_balance(self.OPUS_ID, balance)
    
    def opus_send(self, recieving_address, amount):
         tx = self._token_send(self, self.opus, recieving_address, amount, self.opus_logo)
         self.update_opus_balance()

         return tx
    
    def collective_symbol(self):
        tx = self.hvym_collective.symbol(self.stellar_keypair.public_key)
        return tx.result()
    
    def _safe_contract_call(self, func, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return {'success': True, 'result': result}
        except Exception as e:
            print(f'Contract call failed: {e}')
            return {'success': False, 'error': str(e)}

    def join_collective(self):
        call_result = self._safe_contract_call(
            self.hvym_collective.join,
            caller=self.stellar_keypair.public_key,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            return call_result
        try:
            tx = call_result['result']
            tx.sign_and_submit()
            res = tx.result()
            return {'success': True, 'result': res}
        except Exception as e:
            print(f'Error in join_collective tx: {e}')
            return {'success': False, 'error': str(e)}

    def is_member(self):
        tx = self.hvym_collective.is_member(self.stellar_keypair.public_key)
        return tx.result()
    
    def deploy_node_token(self, name, descriptor):
        call_result = self._safe_contract_call(
            self.hvym_collective.deploy_node_token,
            caller=self.stellar_keypair.public_key,
            name=name,
            descriptor=descriptor,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            return call_result
        try:
            tx = call_result['result']
            tx.sign_and_submit()
            address = tx.result().address
            return {'success': True, 'address': address}
        except Exception as e:
            print(f'Error in deploy_node_token tx: {e}')
            return {'success': False, 'error': str(e)}

    def deploy_ipfs_token(self, name, ipfs_hash, file_type, gateways, _ipns_hash="NONE"):
        call_result = self._safe_contract_call(
            self.hvym_collective.deploy_ipfs_token,
            caller=self.stellar_keypair.public_key,
            name=name,
            ipfs_hash=ipfs_hash,
            file_type=file_type,
            gateways=gateways,
            _ipns_hash=_ipns_hash,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            return call_result
        try:
            tx = call_result['result']
            tx.sign_and_submit()
            self.update_opus_balance()
            self.add_file_token_to_toml(name, ipfs_hash)
            address = tx.result().address
            return {'success': True, 'address': address}
        except Exception as e:
            print(f'Error in deploy_ipfs_token tx: {e}')
            return {'success': False, 'error': str(e)}

    def publish_file(self, ipfs_hash):
        transaction = {'hash': None, 'successful': False, 'transaction_url': None, 'logo': self.stellar_logo}
        call_result = self._safe_contract_call(
            self.hvym_collective.publish_file,
            caller=self.stellar_keypair.public_key,
            publisher=self.stellar_25519_keypair.public_key(),
            ipfs_hash=ipfs_hash,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            transaction['error'] = call_result['error']
            return transaction
        try:
            tx = call_result['result']
            tx.sign()
            send_transaction = self.soroban_server.send_transaction(tx)
            max_attempts = 10
            attempts = 0
            while attempts < max_attempts:
                get_transaction_data = self.soroban_server.get_transaction(send_transaction.hash)
                if get_transaction_data.status != soroban_rpc.GetTransactionStatus.NOT_FOUND:
                    break
                time.sleep(3)
                attempts += 1
            if get_transaction_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
                transaction['hash'] = send_transaction.hash
                transaction['successful'] = True
                transaction['transaction_url'] = self.block_explorer + self.testnet_transaction + transaction['hash']
            else:
                transaction['error'] = f"Transaction status: {get_transaction_data.status}"
        except Exception as e:
            print(f'Error in publish_file tx: {e}')
            transaction['error'] = str(e)
        return transaction

    
    def publish_encrypted_file(self, recipient, ipfs_hash):
        transaction = {'hash': None, 'successful': False, 'transaction_url': None, 'logo': self.stellar_logo}
        
        call_result = self._safe_contract_call(
            self.hvym_collective.publish_encrypted_share,
            caller=self.stellar_keypair.public_key,
            publisher=self.stellar_25519_keypair.public_key(),
            recipient=recipient,
            ipfs_hash=ipfs_hash,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            transaction['error'] = call_result['error']
            return transaction
        try:
            tx = call_result['result']
            tx.sign()
            send_transaction = self.soroban_server.send_transaction(tx)
            max_attempts = 10
            attempts = 0
            while attempts < max_attempts:
                get_transaction_data = self.soroban_server.get_transaction(send_transaction.hash)
                if get_transaction_data.status != soroban_rpc.GetTransactionStatus.NOT_FOUND:
                    break
                time.sleep(3)
                attempts += 1
            if get_transaction_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
                transaction['hash'] = send_transaction.hash
                transaction['successful'] = True
                transaction['transaction_url'] = self.block_explorer + self.testnet_transaction + transaction['hash']
            else:
                transaction['error'] = f"Transaction status: {get_transaction_data.status}"
        except Exception as e:
            print(f'Error in publish_encrypted_file tx: {e}')
            transaction['error'] = str(e)
        return transaction
    
    def add_file_token_to_toml(self, name, cid):
        token_img = os.path.join(self.url_host, 'static', 'file_token.png')
        self.stellar_toml.new_currency(code=f'HVYMFILE_{name}', name=name, issuer=self.stellar_keypair.public_key, display_decimals=0, desc=cid, image=token_img, conditions='This file is owned by the issuer.')
    
    def ipfs_token_balance(self, token_id):
         token = self._bind_ipfs_token(token_id)
         return self._token_balance(token) / 10

    def ipfs_token_mint(self, cid, token_id, recieving_address, amount):
        token = self._bind_ipfs_token(token_id)
        call_result = self._safe_contract_call(
            self._token_mint,
            token,
            recieving_address,
            amount,
            self.stellar_logo,
            True
        )
        if not call_result['success']:
            return call_result
        try:
            tx = call_result['result']
            current_balance = self._token_balance(token)
            if current_balance is not None:
                self.update_file_balance(cid, current_balance)
            return {'success': True, 'tx': tx}
        except Exception as e:
            print(f'Error in ipfs_token_mint: {e}')
            return {'success': False, 'error': str(e)}
    
    def ipfs_custodial_mint(self, cid, token_id, amount):
        return self.ipfs_token_mint(cid, token_id, self.stellar_keypair.public_key, amount)
    
    def ipfs_token_send(self, cid, token_id, recieving_address, amount):
        token = self._bind_ipfs_token(token_id)
        call_result = self._safe_contract_call(
            self._token_send,
            token,
            recieving_address,
            amount,
            self.stellar_logo,
            False
        )
        if not call_result['success']:
            return call_result
        try:
            tx = call_result['result']
            current_balance = self._token_balance(token)
            if current_balance is not None:
                self.update_file_balance(cid, current_balance)
            return {'success': True, 'tx': tx}
        except Exception as e:
            print(f'Error in ipfs_token_send: {e}')
            return {'success': False, 'error': str(e)}
    
    def _bind_ipfs_token(self, token_id):
         return IPFS_Token(token_id, self.soroban_rpc_url, self.NETWORK_PASSPHRASE)
    
    def _token_balance(self, token):
        call_result = self._safe_contract_call(
            token.balance,
            id=self.stellar_keypair.public_key,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            print(f"Error in _token_balance: {call_result['error']}")
            return None
        try:
            tx = call_result['result']
            return tx.result()
        except Exception as e:
            print(f'Error in _token_balance tx: {e}')
            return None
    
    def _token_send(self, token, recieving_address, amount, logo, convert_to_stroops=True):
        transaction = {'hash': None, 'successful': False, 'transaction_url': None, 'logo': logo}
        if convert_to_stroops:
            amount = amount * 10**7
        call_result = self._safe_contract_call(
            token.transfer,
            from_=self.stellar_keypair.public_key,
            to=recieving_address,
            amount=amount,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
        if not call_result['success']:
            transaction['error'] = call_result['error']
            return transaction
        try:
            tx = call_result['result']
            tx.sign()
            send_transaction = self.soroban_server.send_transaction(tx)
            max_attempts = 10
            attempts = 0
            while attempts < max_attempts:
                get_transaction_data = self.soroban_server.get_transaction(send_transaction.hash)
                if get_transaction_data.status != soroban_rpc.GetTransactionStatus.NOT_FOUND:
                    break
                time.sleep(3)
                attempts += 1
            if get_transaction_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
                transaction['hash'] = send_transaction.hash
                transaction['successful'] = True
                transaction['transaction_url'] = self.block_explorer + self.testnet_transaction + transaction['hash']
            else:
                transaction['error'] = f"Transaction status: {get_transaction_data.status}"
        except Exception as e:
            print(f'Error in _token_send tx: {e}')
            transaction['error'] = str(e)
        return transaction
    
    def _token_mint(self, token, recieving_address, amount, logo, file_token= False):
         if not file_token:
             amount = amount * 10**7
             
         transaction = {'hash': None, 'successful': False, 'transaction_url': None, 'logo': logo}
         call_result = self._safe_contract_call(
            token.mint,
            recieving_address,
            amount,
            source=self.stellar_keypair.public_key,
            signer=self.stellar_keypair
        )
         if not call_result['success']:
            transaction['error'] = call_result['error']
            return transaction
         try:
            tx = call_result['result']
            tx.sign()
            send_transaction = self.soroban_server.send_transaction(tx)
            max_attempts = 10
            attempts = 0
            while attempts < max_attempts:
                get_transaction_data = self.soroban_server.get_transaction(send_transaction.hash)
                if get_transaction_data.status != soroban_rpc.GetTransactionStatus.NOT_FOUND:
                    break
                time.sleep(3)
                attempts += 1
            if get_transaction_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
                transaction['hash'] = send_transaction.hash
                transaction['successful'] = True
                transaction['transaction_url'] = self.block_explorer + self.testnet_transaction + transaction['hash']
            else:
                transaction['error'] = f"Transaction status: {get_transaction_data.status}"
         except Exception as e:
            print(f'Error in _token_mint tx: {e}')
            transaction['error'] = str(e)
         return transaction
    
    def _token_symbol(self, token):
        call_result = self._safe_contract_call(
            token.symbol,
            self.stellar_keypair.public_key
        )
        if not call_result['success']:
            print(f"Error in _token_symbol: {call_result['error']}")
            return None
        try:
            tx = call_result['result']
            return tx.result()
        except Exception as e:
            print(f'Error in _token_symbol tx: {e}')
            return None
    
    def _initialize_token_book_data(self):
        xlm_balance = self.stellar_xlm_balance()
        opus_balance = float("{:.2f}".format(self.xlm_to_stroops(self.opus_balance())))

        xlm_data = {'Name': 'xlm', 'TokenId': self.XLM_ID, 'Balance': xlm_balance, 'Logo': self.stellar_logo}
        opus_data = {'Name': 'opus', 'TokenId': self.OPUS_ID, 'Balance': opus_balance, 'Logo': self.opus_logo}
        self._open_db()
        self.token_book.insert(xlm_data)
        self.token_book.insert(opus_data)
        self.db.close()
    
    def _update_token_book_balance(self, token_id, balance):
        self._open_db()
        token = Query()
        self.token_book.update({'Balance': balance}, token.TokenId == token_id)
        all_token_info = self.token_book.all()
        self.db.close()

        return all_token_info
    
    def _get_token_book_balance(self, token_id):
        balance = None
        self._open_db()
        token = Query()
        data = self.token_book.search( token.TokenId == token_id)
        if data != None:
            balance = data['Balance']
        self.db.close()

        return balance
    
    def _custom_qr_code(self, data, cntrImg, out_url, back_color=HVYM_BG_RGB, front_color=HVYM_FG_RGB):
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
        # Ensure directory exists before saving the image
        if not os.path.exists(os.path.dirname(out_url)):
            try:
                os.makedirs(os.path.dirname(out_url))
            except OSError as exc:  # Guard against race condition
                raise
        
        img.save(out_url)
        
        return out_url
    
    def _create_shared_secret(self, b64_pub, server_priv):
        pem_string = self.pem_format(b64_pub)
        pub_key = serialization.load_pem_public_key(pem_string.encode('utf-8'), default_backend())
        shared_secret = server_priv.exchange(ec.ECDH(), pub_key)
        return base64.b64encode(shared_secret).decode('utf-8')
    
    def _create_root_token(self):
        self.root_token = Macaroon(
            location='',
            identifier='PINTHEON_GENERATOR',
            key=self.generate_shared_node_secret()
        ).serialize()
        self._open_db()
        token = Query()
        self.node_keys.update({'root_token': self.root_token}, token.id == 'NODE_KEYS')
        self.db.close()

    def _create_auth_token(self):
        mac = Macaroon(
            location='',
            identifier='PINTHEON_AUTH',
            key=self.generate_shared_session_secret(self._client_session_pub)
        )
        mac.add_first_party_caveat('nonce == '+self.auth_nonce)
        mac.add_first_party_caveat('time < '+ str(self.session_ends))

        self.auth_token  = mac.serialize()

    def _create_stellar_keypair_from_seed(self, seed):
         print('create stellar keypair')
         self.stellar_keypair = Keypair.from_mnemonic_phrase(seed)
         self.stellar_25519_keypair = Stellar25519KeyPair(self.stellar_keypair)

         keypair = { 'name': self.node_name, 'pub': self.stellar_keypair.public_key, 'priv': self.stellar_keypair.secret, '25519_pub' : self.stellar_25519_keypair.public_key() }
         self._open_db()
         self.stellar_book.insert(keypair)
         self.db.close()

         try:
            self.stellar_account = self.stellar_server.accounts().account_id(self.stellar_keypair.public_key).call()
            for balance in self.stellar_account['balances']:
                print(f"Type: {balance['asset_type']}, Balance: {balance['balance']}")
         except Exception as e:
            print("Insufficient balance: "+str(e))
         

    def _load_stellar_keypair(self):
         print('load stellar keypair')
         self._open_db()
         keypair = self.stellar_book.get(doc_id=1)
         self.db.close()
         self.stellar_keypair = Keypair.from_secret(keypair['priv'])
         self.stellar_25519_keypair = Stellar25519KeyPair(self.stellar_keypair)
         
         try:
            self.stellar_account = self.stellar_server.accounts().account_id(self.stellar_keypair.public_key).call()
            for balance in self.stellar_account['balances']:
                print(f"Type: {balance['asset_type']}, Balance: {balance['balance']}")
         except Exception as e:
            print("Insufficient balance: "+str(e))

    def stellar_xlm_balance(self):
        xlm_balance = 0
        for balance in self.stellar_account['balances']:
            if balance['asset_type'] == 'native':
                xlm_balance = balance['balance']
                xlm_balance = float("{:.2f}".format(float(xlm_balance)))

        return xlm_balance

    def stellar_account_balances(self):
        self.stellar_account = self.stellar_server.accounts().account_id(self.stellar_keypair.public_key).call()
        return self.stellar_account['balances']
    
    def stellar_set_logos(self, light_logo, dark_logo):
        self.stellar_logo_light = light_logo
        self.stellar_logo_dark = dark_logo
        self.stellar_logo = self.stellar_logo_light

    def xlm_to_stroops(self, xlm_amount):
        return int(xlm_amount * 10_000_000)

    def stroops_to_xlm(self, stroops):
        return stroops / 10_000_000.0
    
    def stellar_shared_archive(self, file, reciever_pub):
        encrypted_data = None
        file_data = file.read()
        with tempfile.TemporaryDirectory() as temp_dir:
            original_path = os.path.join(temp_dir, file.filename)
            encrypted_path = os.path.join(temp_dir, f"{file.filename}.7z")
            sharedKey = StellarSharedKey(self.stellar_25519_keypair, reciever_pub)
            
            with open(original_path, 'wb') as f:
                f.write(file_data)
            
            with py7zr.SevenZipFile(encrypted_path, 'w', password=sharedKey.hash_of_shared_secret()) as archive:
                archive.write(original_path, os.path.basename(original_path))
            
            with open(encrypted_path, 'rb') as f:
                encrypted_data = f.read()

        return encrypted_data

    @property
    def do_initialize(self):
        self._update_node_data(os.path.join(self.static_path, 'hvym_logo.png'), self._dirs.appname, self._dirs.appauthor, self.node_contract)
        self._update_state_data()
        self._update_customization()
        return True

    @property
    def create_new_node(self):
        print('creating new node...')
        seed = None
        if self.DEBUG:
            seed = DEBUG_SEED
        else:
            seed = self.decrypt_aes(self._seed_cipher, self.generate_shared_session_secret(self._client_session_pub))

        self._create_stellar_keypair_from_seed(seed)

        if self.stellar_account != None and self.stellar_xlm_balance() >= self.XLM_REQUIRED_START_BALANCE:
            self._create_root_token()
            self._update_state_data()
            self._initialize_token_book_data()
            self._update_customization()
            self.active_page = 'establish'
            self.logged_in = True
            self._custom_qr_code(self.stellar_keypair.public_key, './static/stellar_logo.png', './static/stellar_wallet_qr.png', STELLAR_BG_RGB, STELLAR_FG_RGB )
            self._custom_qr_code(self.stellar_keypair.public_key, './static/opus.png', './static/opus_wallet_qr.png', OPUS_BG_RGB, OPUS_FG_RGB )
            return True
        else:
            self._custom_qr_code(self.stellar_keypair.public_key, './static/stellar_logo.png', './static/stellar_wallet_qr.png', STELLAR_BG_RGB, STELLAR_FG_RGB )
            self._custom_qr_code(self.stellar_keypair.public_key, './static/opus.png', './static/opus_wallet_qr.png', OPUS_BG_RGB, OPUS_FG_RGB )
            return False
    
    @property
    def reset_init(self):
        print('resetting node...')
        self.active_page = 'new_node'
        return True
        
    @property
    def on_established(self):
        print('established!!')
        self.view_components = 'dashboard'
        self.active_page = 'authorize'
        self.is_established = True
        self._update_state_data()
        self._update_customization()
        return True
    
    @property
    def activated(self):
        print('activated!!')
        self._update_state_data()
        return True
    
    @property
    def on_resume_state(self):
        print('state_resumed!!')
        self.view_components = 'dashboard'
        self.active_page = 'authorize'
        node_keys = self._get_node_keys()
        node_data = self._get_node_data()
        self.node_pub = node_keys['pub']
        self.node_priv = self.deserialize_private_key(node_keys['priv'])
        self.root_token = node_keys['root_token']
        self._client_node_pub = node_keys['client_pub']
        self.node_name = node_data['node_name']
        self.logo_url = node_data['logo_url']
        self.node_descriptor = node_data['node_descriptor']
        self.url_host = node_data['url_host']
        self.node_contract = node_data['node_contract']
        self.master_key = node_data['master_key']
        self.root_token = node_data['root_token']
        self._update_state_data()
        self._update_customization()
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

    def update_node_data(self):
        print('Update node data...')
        self._open_db()
        data = { 'id': 'NODE_DATA', 'node_name':self.node_name, 'logo_url':self.logo_url, 'node_descriptor':self.node_descriptor, 'url_host':self.url_host, 'node_contract':self.node_contract, 'master_key':self.master_key, 'root_token': self.root_token }
        self._update_table_doc(self.node_data, data)
        print(self.node_data.all())
        self.db.close()
        return data

    def _new_keypair(self):
        priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
        bytes = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pub = bytes.decode('utf-8').replace('\n', '\\n')
        
        return { 'pub': pub, 'priv': priv }
    
    def serialize_private_key(self, private_key):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
    
    def deserialize_private_key(self, serialized_key):
        return serialization.load_pem_private_key(
            serialized_key.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
    
    def _update_state_data(self):
        self._open_db()
        data = { 'id': 'SAVED_STATE', 'current_state':str(self.state), 'established': self.is_established }
        self._update_table_doc(self.state_data, data)
        self.db.close()

    def _update_customization(self):
        self._open_db()
        if self.theme == 2:
            self.stellar_logo = self.stellar_logo_dark
        else:
            self.stellar_logo = self.stellar_logo_light

        data = { 'current_theme': self.theme, 'themes': self.themes, 'bg_img': self.bg_img, 'logo': self.stellar_logo, 'opus_logo': self.opus_logo, 'boros_logo': self.boros_logo }
        self._update_table_doc(self.customization, data)
        self.db.close()

    def _update_node_data(self, logo_url, name, descriptor, node_contract):
        self.logo_url = logo_url
        self.node_name = name
        self.node_descriptor = descriptor
        self.node_contract = node_contract
        self.update_node_data()

    def _initialize_db(self):
        self._open_db()
        self.db.close()

    def _update_table_doc(self, table, data, id=1):
        if not table.contains(doc_id=id):
            table.insert(data)
        else:
            table.update(data)

    def _open_db(self):
        self.db = TinyDB(encryption_key=self.master_key, path=self.db_path, storage=tae.EncryptedJSONStorage)
        self.state_data = self.db.table('state_data')
        self.node_data = self.db.table('node_data')
        self.node_keys = self.db.table('node_keys')
        self.customization = self.db.table('customization')
        self.file_book= self.db.table('file_book')
        self.peer_book= self.db.table('peer_book')
        self.stellar_book= self.db.table('stellar_book')
        self.token_book= self.db.table('token_book')
        self.namespaces= self.db.table('namespaces')
        self.access_tokens= self.db.table('access_tokens')

    def _get_node_data(self):
        result = None
        self._open_db()
        file = Query()
        record = self.node_data.get(file.id == 'NODE_DATA')
        if record != None:
            result = record
        self.db.close()
        return result

    def _get_node_keys(self):
        result = None
        self._open_db()
        file = Query()
        record = self.node_keys.get(file.id == 'NODE_KEYS')
        if record != None:
            result = record
        self.db.close()
        return result

    def _get_saved_state(self):
        result = None
        self._open_db()
        file = Query()
        record = self.state_data.get(file.id == 'SAVED_STATE')
        if record != None:
            self.is_established = record['established']
            result = record['current_state']
        self.db.close()
        return result
    
    def _get_saved_established_state(self):
        result = False
        if os.path.isfile(self.db_path):
            self._open_db()
            file = Query()
            record = self.state_data.get(file.id == 'SAVED_STATE')
            if record != None:
                result = record['established']
            self.db.close()
        self.is_established = result
        return result

    def get_customization(self):
        result = None
        self._open_db()
        result = self.customization.all()[0]
        self.db.close()

        return result
    
    def update_customization(self):
        self._update_customization()

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
        
    def get_files(self):
        self._open_db()
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
        
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

    def file_exists(self, file_name, file_type):
        result = False
        self._open_db()
        file = Query()
        record = self.file_book.get(file.Name == file_name)

        if record != None:
            result = True

        self.db.close()

        return result

    def update_file_as_logo(self, file_name):
        self._open_db()
        file = Query()
        record = self.file_book.get(file.Name == file_name)

        if record != None and record['IsLogo'] == False:
            self.file_book.update({'IsLogo': False})
            self.file_book.update({'IsLogo': True}, file.Name == file_name)

        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
    
    def update_file_as_bg_img(self, file_name):
        self._open_db()
        file = Query()
        record = self.file_book.get(file.Name == file_name)

        if record != None and record['IsBgImg'] == False:
            self.file_book.update({'IsBgImg': False})
            self.file_book.update({'IsBgImg': True}, file.Name == file_name)

        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
    
    def remove_file_as_bg_img(self):
        self._open_db()
        self.file_book.update({'IsBgImg': False})
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
    
    def file_data_from_cid(self, cid):
        self._open_db()
        file = Query()
        file_data = self.file_book.get(file.CID==cid)
        self.db.close()

        return file_data
    
    def update_file_contract_id(self, cid, contract_id):
        self._open_db()
        file = Query()
        self.file_book.update({'ContractID': contract_id}, file.CID == cid)
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
    
    def update_file_balance(self, cid, balance):
        self._open_db()
        file = Query()
        self.file_book.update({'Balance': balance}, file.CID == cid)
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info

    def all_file_info(self):
        self._open_db()
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info
    
    def add_access_token(self, name, stellar_25519_pub):
        builder = StellarSharedKeyTokenBuilder(self.stellar_25519_keypair, stellar_25519_pub)
        data = { 'name': name, 'pub': stellar_25519_pub }
        self._open_db()
        file = Query()

        record = self.access_tokens.get(file.pub == stellar_25519_pub)
        if record == None:
            self.access_tokens.insert(data)
        else:
            self.access_tokens.update(data, file.pub == stellar_25519_pub)
        self.db.close()

        return builder.serialize()
    
    def remove_access_token(self, stellar_25519_pub):
        self._open_db()
        file = Query()
        if len(self.access_tokens.search(file.pub == stellar_25519_pub))>0:
                self.access_tokens.remove(file.pub == stellar_25519_pub)

        all_token_info = self.access_tokens.all()
        self.db.close()

        return all_token_info
    
    def authorize_access_token(self, access_token):
        tokenVerifier = StellarSharedKeyTokenVerifier(self.stellar_25519_keypair, access_token)
        return tokenVerifier.valid()
    
    def all_access_token_info(self):
        self._open_db()
        all_token_info = self.access_tokens.all()
        self.db.close()

        return all_token_info

    def ipfs_repo_stats(self):
        url = f'{self.ipfs_endpoint}/repo/stat?size-only=false&human=true'
        response = requests.post(url);

        if response.status_code == 200:
                return response
        else:
                return jsonify({'error': 'stats not available.'}), 400

    def add_file_to_ipfs(self, file_name, file_type, file_data, is_logo=False, is_bg_img=False, encrypted=False, reciever_pub=None):
        if self.FAKE_IPFS:
            return self.create_fake_ipfs_data()
        else:
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
                    
                    file_info = {'Name':ipfs_data['Name'], 'Type': file_type, 'Encrypted': encrypted, 'Hash':ipfs_data['Hash'], 'CID':cid, 'ContractID': "", 'Size':ipfs_data['Size'], 'IsLogo':is_logo, 'IsBgImg': is_bg_img, 'Balance': 0, 'RecieverPub':reciever_pub}
                    self._open_db()

                    if is_logo:
                        self.file_book.update({'IsLogo': False})

                    if is_bg_img:
                        self.file_book.update({'IsBgImg': False})

                    self.file_book.insert(file_info)

                    all_file_info = self.file_book.all()
                    self.db.close()

                    return all_file_info
            else:
                return None
        
    def create_fake_ipfs_data(self):
        names = ['test1.png', 'test2.png', 'test3.png']
        types = ['image/png', 'image/png', 'image/png']
        logo = [False, True, False]
        bg_img = [False, False, False]

        idx = 0
        self._open_db()
        File = Query()
        for hash in FAKE_IPFS_FILES:
            self.file_book.remove(File.CID == hash)
            file_info = {'Name':names[idx], 'Type': types[idx], 'Encrypted': False, 'Hash':hash, 'CID':hash, 'ContractID': "", 'Size':1.0, 'IsLogo':logo[idx], 'IsBgImg': bg_img[idx], 'Balance': 0, 'RecieverPub':None}
            self.file_book.insert(file_info)
            idx+=1
        all_file_info = self.file_book.all()
        self.db.close()

        return all_file_info

    
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
        # Ensure host is always just the hostname, not a full URL
        host = self.url_host
        if host and '://' in host:
            # Extract hostname from full URL
            from urllib.parse import urlparse
            parsed = urlparse(host)
            host = parsed.netloc
        
        result = {'name': self.node_name, 'descriptor':self.node_descriptor, 'address': self.stellar_keypair.public_key, '25519_pub': self.stellar_25519_keypair.public_key(), 'logo': self.logo_url, 'host': host, 'customization': None, 'token_info': None, 'stats': None, 'repo': None, 'nonce': self.auth_nonce, 'stats':None, 'file_list':None, 'peer_id': None, 'expires': str(self.session_ends), 'authorized': True, 'transaction_data': None, 'access_tokens': []}
        if self.FAKE_IPFS:
            #If FAKE IPFS we just create dummy ipfs data
            stats = {'RateIn': 1000, 'RateOut':1000, 'TotalIn': 1000, 'TotalOut': 1000}
            repo = {'RepoSize': "0.1", 'StorageMax':"9000", 'usedPercentage': 0.01}
            self._open_db()
            files_list = self.file_book.all()
            customization = self.customization.all()
            token_info = self.token_book.all()
            access_tokens = self.access_tokens.all()
            self.db.close()
            result['customization'] = customization[0]
            result['token_info'] = token_info
            result['repo'] = repo
            result['file_list'] = files_list
            result['peer_id'] = 'FAKE-PEER-ID'
            result['access_tokens'] = access_tokens
        else:
            self._open_db()
            repo_response = self.ipfs_repo_stats()
            files_list = self.file_book.all()
            customization = self.customization.all()
            token_info = self.token_book.all()
            peer_id_response = self.get_peer_id()
            access_tokens = self.access_tokens.all()
            self.db.close()


            if repo_response.status_code == 200:
                repo = repo_response.json()
                repo['RepoSize'] = repo['RepoSize'] / (1024 * 1024)
                repo['StorageMax'] = repo['StorageMax'] / (1024 * 1024)
                repo['usedPercentage'] = (repo['RepoSize'] / repo['StorageMax']) * 100
                repo['RepoSize'] = f"{repo['RepoSize']:.2f}"
                repo['StorageMax'] = f"{repo['StorageMax']:.2f}"
                
                del repo['RepoPath']
                del repo['Version']
                result['repo'] = repo

            result['access_tokens'] = access_tokens

            if customization != None:
                result['customization'] = customization[0]

            if token_info != None:
                result['token_info'] = token_info

            if files_list != None:
                result['file_list'] = files_list

            if peer_id_response.status_code == 200:
                result['peer_id'] = peer_id_response.json()['Value']

        return result

    def get_settings_data(self):
        result = {'peer_id':None, 'peer_list':None}
        self._open_db()
        peer_id_response = self.get_peer_id()
        peers = self.peer_book.all()
        self.db.close()

        if peer_id_response.status_code == 200:
                result['peer_id'] = peer_id_response.json()['Value']

        result['peer_list'] = peers

        return result