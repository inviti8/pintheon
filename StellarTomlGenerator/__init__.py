import os
import toml
import io

class StellarTomlGenerator:
    def __init__(
        self,
        file_path,
        org_name=None,
        org_dba=None,
        org_url=None,
        org_official_email=None,
        org_support_email=None,
        org_twitter=None,
        org_description=None,
        version=None,
        network_passphrase=None,
        accounts=None
    ):
        self.file_path = os.path.join(file_path, 'stellar.toml')
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
            self.version = data.get('VERSION')
            self.network_passphrase = data.get('NETWORK_PASSPHRASE')
            self.accounts = data.get('ACCOUNTS', [])
            self.documentation = data.get('DOCUMENTATION', {})
        else:
            self.version = version
            self.network_passphrase = network_passphrase
            self.accounts = accounts or []
            self.documentation = {
                'ORG_NAME': org_name,
                'ORG_DBA': org_dba,
                'ORG_URL': org_url,
                'ORG_OFFICIAL_EMAIL': org_official_email,
                'ORG_SUPPORT_EMAIL': org_support_email,
                'ORG_TWITTER': org_twitter,
                'ORG_DESCRIPTION': org_description
            }
            self._ensure_toml()

    def _ensure_toml(self):
        if not os.path.exists(self.file_path):
            self._create_toml()
        else:
            self._update_toml()

    def _write_toml_with_spacing(self, data):
        # Write TOML to a string buffer
        buf = io.StringIO()
        toml.dump(data, buf)
        content = buf.getvalue()
        # Insert a blank line between ACCOUNTS and the first [[CURRENCIES]]
        if 'CURRENCIES' in data:
            content = content.replace('\n[[CURRENCIES]]', '\n\n[[CURRENCIES]]', 1)
        with open(self.file_path, 'w') as f:
            f.write(content)

    def _create_toml(self):
        data = {
            'VERSION': self.version,
            'NETWORK_PASSPHRASE': self.network_passphrase,
            'ACCOUNTS': self.accounts,
            'DOCUMENTATION': self.documentation
        }
        self._write_toml_with_spacing(data)

    def _update_toml(self):
        with open(self.file_path, 'r') as f:
            data = toml.load(f)
        data['DOCUMENTATION'] = self.documentation
        data['VERSION'] = self.version
        data['NETWORK_PASSPHRASE'] = self.network_passphrase
        # Ensure ACCOUNTS is present and up to date
        if 'ACCOUNTS' not in data:
            data['ACCOUNTS'] = self.accounts
        else:
            # Merge unique accounts
            existing = set(data['ACCOUNTS'])
            for acc in self.accounts:
                if acc not in existing:
                    data['ACCOUNTS'].append(acc)
        self._write_toml_with_spacing(data)

    def new_currency(self, code, name, issuer, display_decimals, desc, image, conditions, is_asset_anchored=False):
        currency_entry = {
            'code': code,
            'name': name,
            'issuer': issuer,
            'is_asset_anchored': is_asset_anchored,
            'display_decimals': display_decimals,
            'desc': desc,
            'image': image,
            'conditions': conditions
        }
        # Load existing TOML
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
        else:
            data = {}
        # Check for existing currency by code
        currencies = data.get('CURRENCIES', [])
        if not isinstance(currencies, list):
            currencies = [currencies]
        for idx, curr in enumerate(currencies):
            if curr.get('code') == code:
                self.update_currency(code, currency_entry)
                return
        # Append new currency
        currencies.append(currency_entry)
        data['CURRENCIES'] = currencies
        self._write_toml_with_spacing(data)

    def update_currency(self, code, new_data):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
        else:
            return  # Nothing to update
        currencies = data.get('CURRENCIES', [])
        if not isinstance(currencies, list):
            currencies = [currencies]
        updated = False
        for idx, curr in enumerate(currencies):
            if curr.get('code') == code:
                currencies[idx] = new_data
                updated = True
                break
        if updated:
            data['CURRENCIES'] = currencies
            self._write_toml_with_spacing(data)

    def add_account(self, public_key):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
        else:
            data = {}
        accounts = data.get('ACCOUNTS', [])
        if public_key not in accounts:
            accounts.append(public_key)
            data['ACCOUNTS'] = accounts
            self._write_toml_with_spacing(data)

    def update_version(self, new_version):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
        else:
            data = {}
        data['VERSION'] = new_version
        self._write_toml_with_spacing(data)
        self.version = new_version

    def update_network_passphrase(self, new_passphrase):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                data = toml.load(f)
        else:
            data = {}
        data['NETWORK_PASSPHRASE'] = new_passphrase
        self._write_toml_with_spacing(data)
        self.network_passphrase = new_passphrase 