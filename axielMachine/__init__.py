"""Finite state machine for node."""

__version__ = "0.01"
import os
import json
import requests
import subprocess
from transitions import Machine, State
from cryptography.fernet import Fernet 

class AxielMachine(object):

    states = [State(name='spawned', on_enter=['on_spawn']), 'initializing', 'establishing', 'idle', 'handling_file', 'redeeming']

    def __init__(self, wallet_path, xelis_daemon, ipfs_daemon, xelis_network="Mainnet"):

        self.id = Fernet.generate_key()
        self.wallet_path = wallet_path
        self.xelis_daemon = xelis_daemon
        self.ipfs_daemon = ipfs_daemon
        self.xelis_network = xelis_network

        # Initialize the state machine
        self.machine = Machine(model=self, states=AxielMachine.states, initial='spawned')

        self.machine.add_transition(trigger='initialize', source='spawned', dest='initializing', conditions=['do_initialize'])

        self.machine.add_transition(trigger='establish', source='initializing', dest='establishing', conditions=['do_establish'])

        self.machine.add_transition(trigger='established', source='establishing', dest='idle', conditions=['on_established'])

        self.machine.add_transition(trigger='handle_file', source='idle', dest='handling_file', conditions=['do_handle_file'])

        self.machine.add_transition(trigger='handled_file', source='handling_file', dest='idle', conditions=['on_file_handled'])

        self.machine.add_transition(trigger='redeem', source='idle', dest='redeeming', conditions=['do_redeem'])

        self.machine.add_transition(trigger='redeemed', source='redeeming', dest='idle', conditions=['on_redeemed'])

        def on_spawn(self):
            print('spawned')
            self.initialize()

        def do_initialize(self):
            print('initializing')

        def do_establish(self):
            print('establishing')
        
        def on_established(self):
            print('established')

        def do_redeem(self):
            print('redeem')

        def on_redeemed(self):
            print('redeemed')

        def do_handle_file(self):
            print('handle file')

        def on_file_handled(self):
            print('file handled')

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