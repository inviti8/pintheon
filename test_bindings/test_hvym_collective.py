#!/usr/bin/env python3
"""
Consolidated test script for HVYM Collective functionality.

Usage:
    python test_hvym_collective.py [stellar_secret]

If no secret is provided, it will use the default testnet account.
"""
import os
import sys
import time
import argparse
from stellar_sdk import Keypair, Network, Server, SorobanServer, soroban_rpc, scval
from stellar_sdk import xdr as stellar_xdr
from hvym_collective_bindings import Client as Collective
from dotenv import load_dotenv

# Default testnet account (public key: GCZBDOK3UL5AZWHQLKTHG5JATJ3JNUJWFOY5EORHTAG2LBTL7WJHS7P4)
DEFAULT_TESTNET_SECRET = "SBHJTBPQSMDUP67GZD6RS2GIR7GP2R7HDVR3D7VWUBMGHYF663GY5SJC"
TESTNET_SOROBAN_SERVER = "https://soroban-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
COLLECTIVE_CONTRACT_ID = "CBVM3CP5YEYZFMWLT4A5UCI2DSUQMUJ3URCHYO2YJNRPS5S4D75QJG2N"

class HVYMCollectiveTester:
    def __init__(self, stellar_secret=None):
        """Initialize the tester with an optional Stellar secret."""
        self.stellar_secret = stellar_secret or DEFAULT_TESTNET_SECRET
        self.keypair = Keypair.from_secret(self.stellar_secret)
        self.soroban_server = SorobanServer(TESTNET_SOROBAN_SERVER)
        self.collective = None
        self.test_results = {
            'join_collective': False,
            'deploy_node_token': False,
            'deploy_ipfs_token': False
        }
        self.node_contract_address = None
        self.ipfs_contract_address = None

    def _safe_contract_call(self, func, *args, **kwargs):
        """Safely call a contract function with error handling."""
        try:
            print(f"\n=== Contract Call Debug ===")
            print(f"Function: {func.__name__}")
            print(f"Args: {args}")
            print(f"Kwargs: {kwargs}")
            
            # Make the actual contract call
            print("Making contract call...")
            result = func(*args, **kwargs)
            print("Contract call successful")
            
            if hasattr(result, '__dict__'):
                print(f"Result type: {type(result).__name__}")
                print(f"Result attributes: {[attr for attr in dir(result) if not attr.startswith('__')]}")
            
            return {'success': True, 'result': result}
        except Exception as e:
            print(f'Contract call failed: {e}')
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}

    def _wait_for_transaction(self, tx_hash, max_attempts=10):
        """Wait for a transaction to be confirmed."""
        print(f"\n=== Waiting for transaction confirmation ===")
        attempts = 0
        while attempts < max_attempts:
            tx_data = self.soroban_server.get_transaction(tx_hash)
            if tx_data.status != soroban_rpc.GetTransactionStatus.NOT_FOUND:
                print(f"Transaction status: {tx_data.status}")
                return tx_data
            time.sleep(3)
            attempts += 1
        print("Timed out waiting for transaction confirmation")
        return None

    def setup(self):
        """Setup the test environment."""
        print(f"\n=== Setting up test environment ===")
        print(f"Using account: {self.keypair.public_key}")
        
        # Initialize HVYM Collective client
        self.collective = Collective(
            COLLECTIVE_CONTRACT_ID, 
            TESTNET_SOROBAN_SERVER, 
            NETWORK_PASSPHRASE
        )
        print(f"Initialized HVYM Collective client with contract ID: {COLLECTIVE_CONTRACT_ID}")

    def test_join_collective(self):
        """Test joining the HVYM Collective."""
        print("\n=== Testing HVYM Collective Join ===")
        
        # First, check if already a member
        print("\n=== Checking membership status ===")
        from stellar_sdk import Address
        address = Address(self.keypair.public_key)
        is_member_tx = self.collective.is_member(address)
        
        try:
            is_member = is_member_tx.simulate().result()
            print(f"Is member: {is_member}")
            
            if is_member:
                print("Account is already a member of the HVYM Collective")
                self.test_results['join_collective'] = True
                return True
                
        except Exception as e:
            print(f"Error checking membership: {e}")
            return False
            
        # Join the collective
        print("\n=== Joining HVYM Collective ===")
        join_tx = self.collective.join(
            caller=self.keypair.public_key,
            source=self.keypair.public_key,
            signer=self.keypair
        )
        
        print("\n=== Processing join transaction ===")
        join_tx.sign()
        send_transaction = self.soroban_server.send_transaction(join_tx)
        print(f"Transaction submitted. Hash: {send_transaction.hash}")
        
        # Wait for transaction confirmation
        tx_data = self._wait_for_transaction(send_transaction.hash)
        if not tx_data:
            print("Error: Could not get transaction data")
            return False
            
        if tx_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
            print("\n✅ Successfully joined the HVYM Collective!")
            
            # Verify membership
            print("\n=== Verifying membership ===")
            is_member_tx = self.collective.is_member(address)
            is_member = is_member_tx.simulate().result()
            print(f"Is member: {is_member}")
            
            if is_member:
                print("✅ Membership verified successfully!")
                self.test_results['join_collective'] = True
                return True
            else:
                print("❌ Failed to verify membership after join")
                return False
        else:
            print(f"❌ Transaction failed with status: {tx_data.status}")
            if hasattr(tx_data, 'result_xdr') and tx_data.result_xdr:
                print(f"Result XDR: {tx_data.result_xdr}")
            return False

    def test_deploy_node_token(self):
        """Test deploying a node token."""
        if not self.test_results['join_collective']:
            print("Skipping node token deployment: Must be a collective member first")
            return False
            
        print("\n=== Testing HVYM Collective Deploy Node Token ===")
        
        # Node details with timestamp for uniqueness
        import time
        timestamp = str(int(time.time()))
        node_name = f"Test Node {timestamp}".encode()
        node_descriptor = f"Test Node Description {timestamp}".encode()
        
        print(f"\n=== Deploying Node Token ===")
        print(f"Node Name: {node_name.decode()}")
        print(f"Node Descriptor: {node_descriptor.decode()}")
        
        # Deploy the node token
        deploy_tx = self.collective.deploy_node_token(
            caller=self.keypair.public_key,
            name=node_name,
            descriptor=node_descriptor,
            source=self.keypair.public_key,
            signer=self.keypair
        )
        
        print("\n=== Processing deploy transaction ===")
        deploy_tx.sign()
        send_transaction = self.soroban_server.send_transaction(deploy_tx)
        print(f"Transaction submitted. Hash: {send_transaction.hash}")
        
        # Wait for transaction confirmation
        tx_data = self._wait_for_transaction(send_transaction.hash)
        if not tx_data:
            print("Error: Could not get transaction data")
            return False
            
        if tx_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
            try:
                # Get the deployed contract address
                self.node_contract_address = deploy_tx.result().address
                print(f"\n✅ Successfully deployed node token contract!")
                print(f"Contract address: {self.node_contract_address}")
                self.test_results['deploy_node_token'] = True
                return True
                
            except Exception as addr_error:
                print(f"Warning: Could not get address from tx.result(): {addr_error}")
                print(f"Transaction hash: {send_transaction.hash}")
                return False
        else:
            print(f"❌ Transaction failed with status: {tx_data.status}")
            if hasattr(tx_data, 'result_xdr') and tx_data.result_xdr:
                print(f"Result XDR: {tx_data.result_xdr}")
            return False

    def test_deploy_ipfs_token(self):
        """Test deploying an IPFS token."""
        if not self.test_results['deploy_node_token']:
            print("Skipping IPFS token deployment: Must deploy node token first")
            return False
            
        print("\n=== Testing HVYM Collective Deploy IPFS Token ===")
        
        # IPFS token details with timestamp for uniqueness
        import time
        timestamp = str(int(time.time()))
        token_name = f"Test IPFS Token {timestamp}".encode()
        # Generate a unique IPFS hash by appending timestamp
        ipfs_hash = f"QmXxT5f8A1LdLkPyf8XJ4pX8XJ4pX8XJ4pX8XJ4pX8XJ4pX_{timestamp}".encode()
        file_type = b"image/png"
        gateways = f"https://ipfs.io/ipfs/{timestamp}".encode()
        _ipns_hash = None  # Optional, can be None
        
        print(f"\n=== Deploying IPFS Token ===")
        print(f"Token Name: {token_name.decode()}")
        print(f"IPFS Hash: {ipfs_hash.decode()}")
        print(f"File Type: {file_type.decode()}")
        print(f"Gateways: {gateways.decode()}")
        
        # Deploy the IPFS token
        deploy_tx = self.collective.deploy_ipfs_token(
            caller=self.keypair.public_key,
            name=token_name,
            ipfs_hash=ipfs_hash,
            file_type=file_type,
            gateways=gateways,
            _ipns_hash=_ipns_hash,
            source=self.keypair.public_key,
            signer=self.keypair
        )
        
        print("\n=== Processing deploy transaction ===")
        deploy_tx.sign()
        send_transaction = self.soroban_server.send_transaction(deploy_tx)
        print(f"Transaction submitted. Hash: {send_transaction.hash}")
        
        # Wait for transaction confirmation
        tx_data = self._wait_for_transaction(send_transaction.hash)
        if not tx_data:
            print("Error: Could not get transaction data")
            return False
            
        if tx_data.status == soroban_rpc.GetTransactionStatus.SUCCESS:
            try:
                # Get the deployed contract address
                self.ipfs_contract_address = deploy_tx.result().address
                print(f"\n✅ Successfully deployed IPFS token contract!")
                print(f"Contract address: {self.ipfs_contract_address}")
                self.test_results['deploy_ipfs_token'] = True
                return True
                
            except Exception as addr_error:
                print(f"Warning: Could not get address from tx.result(): {addr_error}")
                print(f"Transaction hash: {send_transaction.hash}")
                return False
        else:
            print(f"❌ Transaction failed with status: {tx_data.status}")
            if hasattr(tx_data, 'result_xdr') and tx_data.result_xdr:
                print(f"Result XDR: {tx_data.result_xdr}")
            return False

    def run_tests(self):
        """Run all tests in sequence."""
        print("\n" + "="*80)
        print("   HVYM COLLECTIVE TEST SUITE")
        print("="*80)
        
        self.setup()
        
        # Run tests in sequence
        print("\n" + "="*80)
        print("1. TESTING: JOIN COLLECTIVE")
        print("="*80)
        self.test_join_collective()
        
        print("\n" + "="*80)
        print("2. TESTING: DEPLOY NODE TOKEN")
        print("="*80)
        self.test_deploy_node_token()
        
        print("\n" + "="*80)
        print("3. TESTING: DEPLOY IPFS TOKEN")
        print("="*80)
        self.test_deploy_ipfs_token()
        
        # Print summary
        print("\n" + "="*80)
        print("   TEST SUMMARY")
        print("="*80)
        for test_name, passed in self.test_results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"{status} - {test_name}")
        
        if all(self.test_results.values()):
            print("\n✅ ALL TESTS PASSED!")
            return True
        else:
            print("\n❌ SOME TESTS FAILED!")
            return False

def main():
    """Main function to parse arguments and run tests."""
    parser = argparse.ArgumentParser(description='Test HVYM Collective functionality')
    parser.add_argument('--secret', type=str, help='Stellar secret key', default=None)
    args = parser.parse_args()
    
    tester = HVYMCollectiveTester(stellar_secret=args.secret)
    success = tester.run_tests()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
