"""
Test script to debug Soroban contract bindings.
Tests the hvym_collective_bindings, opus_bindings, and ipfs_token_bindings.
"""

import sys
import os
import traceback
import importlib.util

from stellar_sdk import Keypair, Network, SorobanServer

# Load bindings directly without going through pintheonMachine/__init__.py
def load_module_from_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

bindings_dir = os.path.join(os.path.dirname(__file__), 'pintheonMachine')
hvym_collective = load_module_from_file('hvym_collective_bindings', os.path.join(bindings_dir, 'hvym_collective_bindings.py'))
opus_bindings = load_module_from_file('opus_bindings', os.path.join(bindings_dir, 'opus_bindings.py'))
ipfs_token = load_module_from_file('ipfs_token_bindings', os.path.join(bindings_dir, 'ipfs_token_bindings.py'))

Collective = hvym_collective.Client
Opus = opus_bindings.Client
IPFS_Token = ipfs_token.Client

# Test configuration
TEST_SECRET_KEY = 'SDBH2Y33VOZWF3BIGDR6NYMXIY4JRHO4Q6QOYICX4PJTV7AI4EX72CWT'
SOROBAN_RPC_URL = 'https://soroban-testnet.stellar.org'
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE

# Contract IDs
COLLECTIVE_ID = 'CDHSOV4IKQB3YZTA6HW26RN7VS6UVZRZZCNWDQVCSQPKYKBMATRJSQ5R'
OPUS_ID = 'CA3SLEQ65R3DAYT5GPFB6SXAHTR5NS5VAEZSEMMIYNXWMTLBT7NX2RHX'
XLM_ID = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC'


def _to_bytes(value):
    """Convert a string to bytes, or return as-is if already bytes."""
    if value is None:
        return None
    return value.encode('utf-8') if isinstance(value, str) else value


def test_connection():
    """Test basic Soroban connection."""
    print("\n" + "="*60)
    print("TEST: Soroban Connection")
    print("="*60)

    try:
        server = SorobanServer(SOROBAN_RPC_URL)
        health = server.get_health()
        print(f"[PASS] Soroban server healthy: {health}")

        ledger = server.get_latest_ledger()
        print(f"[PASS] Latest ledger: {ledger.sequence}")
        return True
    except Exception as e:
        print(f"[FAIL] Connection failed: {e}")
        traceback.print_exc()
        return False


def test_keypair():
    """Test keypair creation from secret."""
    print("\n" + "="*60)
    print("TEST: Keypair")
    print("="*60)

    try:
        keypair = Keypair.from_secret(TEST_SECRET_KEY)
        print(f"[PASS] Public key: {keypair.public_key}")
        return keypair
    except Exception as e:
        print(f"[FAIL] Keypair creation failed: {e}")
        traceback.print_exc()
        return None


def test_collective_read_only(collective, keypair):
    """Test read-only collective contract calls."""
    print("\n" + "="*60)
    print("TEST: Collective Read-Only Calls")
    print("="*60)

    results = {}

    # Test symbol()
    print("\n--- Testing symbol() ---")
    try:
        tx = collective.symbol(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] symbol(): {result}")
        results['symbol'] = result
    except Exception as e:
        print(f"[FAIL] symbol() failed: {e}")
        traceback.print_exc()
        results['symbol'] = None

    # Test join_fee()
    print("\n--- Testing join_fee() ---")
    try:
        tx = collective.join_fee(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] join_fee(): {result}")
        results['join_fee'] = result
    except Exception as e:
        print(f"[FAIL] join_fee() failed: {e}")
        traceback.print_exc()
        results['join_fee'] = None

    # Test mint_fee()
    print("\n--- Testing mint_fee() ---")
    try:
        tx = collective.mint_fee(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] mint_fee(): {result}")
        results['mint_fee'] = result
    except Exception as e:
        print(f"[FAIL] mint_fee() failed: {e}")
        traceback.print_exc()
        results['mint_fee'] = None

    # Test is_launched()
    print("\n--- Testing is_launched() ---")
    try:
        tx = collective.is_launched(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] is_launched(): {result}")
        results['is_launched'] = result
    except Exception as e:
        print(f"[FAIL] is_launched() failed: {e}")
        traceback.print_exc()
        results['is_launched'] = None

    # Test is_member()
    print("\n--- Testing is_member() ---")
    try:
        tx = collective.is_member(
            caller=keypair.public_key,
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] is_member(): {result}")
        results['is_member'] = result
    except Exception as e:
        print(f"[FAIL] is_member() failed: {e}")
        traceback.print_exc()
        results['is_member'] = None

    # Test is_admin()
    print("\n--- Testing is_admin() ---")
    try:
        tx = collective.is_admin(
            caller=keypair.public_key,
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] is_admin(): {result}")
        results['is_admin'] = result
    except Exception as e:
        print(f"[FAIL] is_admin() failed: {e}")
        traceback.print_exc()
        results['is_admin'] = None

    # Test opus_address()
    print("\n--- Testing opus_address() ---")
    try:
        tx = collective.opus_address(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] opus_address(): {result}")
        results['opus_address'] = result
    except Exception as e:
        print(f"[FAIL] opus_address() failed: {e}")
        traceback.print_exc()
        results['opus_address'] = None

    # Test opus_reward()
    print("\n--- Testing opus_reward() ---")
    try:
        tx = collective.opus_reward(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] opus_reward(): {result}")
        results['opus_reward'] = result
    except Exception as e:
        print(f"[FAIL] opus_reward() failed: {e}")
        traceback.print_exc()
        results['opus_reward'] = None

    # Test opus_split()
    print("\n--- Testing opus_split() ---")
    try:
        tx = collective.opus_split(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] opus_split(): {result}")
        results['opus_split'] = result
    except Exception as e:
        print(f"[FAIL] opus_split() failed: {e}")
        traceback.print_exc()
        results['opus_split'] = None

    return results


def test_opus_read_only(opus, keypair):
    """Test read-only Opus token contract calls."""
    print("\n" + "="*60)
    print("TEST: Opus Token Read-Only Calls")
    print("="*60)

    results = {}

    # Test symbol()
    print("\n--- Testing symbol() ---")
    try:
        tx = opus.symbol(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] symbol(): {result}")
        results['symbol'] = result
    except Exception as e:
        print(f"[FAIL] symbol() failed: {e}")
        traceback.print_exc()
        results['symbol'] = None

    # Test decimals()
    print("\n--- Testing decimals() ---")
    try:
        tx = opus.decimals(
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] decimals(): {result}")
        results['decimals'] = result
    except Exception as e:
        print(f"[FAIL] decimals() failed: {e}")
        traceback.print_exc()
        results['decimals'] = None

    # Test balance()
    print("\n--- Testing balance() ---")
    try:
        tx = opus.balance(
            id=keypair.public_key,
            source=keypair.public_key,
            signer=keypair
        )
        result = tx.result()
        print(f"[PASS] balance(): {result}")
        results['balance'] = result
    except Exception as e:
        print(f"[FAIL] balance() failed: {e}")
        traceback.print_exc()
        results['balance'] = None

    return results


def test_join_collective(collective, keypair):
    """Test joining the collective."""
    print("\n" + "="*60)
    print("TEST: Join Collective (Write Operation)")
    print("="*60)

    try:
        print(f"Attempting to join collective as {keypair.public_key}...")
        tx = collective.join(
            caller=keypair.public_key,
            source=keypair.public_key,
            signer=keypair
        )
        print(f"Transaction built, signing and submitting...")

        # Use sign_and_submit() to actually send to the network
        tx.sign_and_submit()

        print(f"Transaction submitted!")
        print(f"  Hash: {tx.transaction.hash_hex() if hasattr(tx, 'transaction') and tx.transaction else 'N/A'}")

        result = tx.result()
        print(f"[PASS] join() succeeded: {result}")
        return True
    except Exception as e:
        print(f"[FAIL] join() failed: {e}")
        traceback.print_exc()
        return False


def test_deploy_node_token(collective, keypair):
    """Test deploying a node token."""
    print("\n" + "="*60)
    print("TEST: Deploy Node Token (Write Operation)")
    print("="*60)

    name = "TestNode"
    descriptor = "Test node descriptor"

    try:
        print(f"Attempting to deploy node token...")
        print(f"  name: {name}")
        print(f"  descriptor: {descriptor}")

        tx = collective.deploy_node_token(
            caller=keypair.public_key,
            name=_to_bytes(name),
            descriptor=_to_bytes(descriptor),
            source=keypair.public_key,
            signer=keypair
        )
        print(f"Transaction built, signing and submitting...")

        # Use sign_and_submit() to actually send to the network
        tx.sign_and_submit()

        print(f"Transaction submitted!")
        print(f"  Hash: {tx.transaction.hash_hex() if hasattr(tx, 'transaction') and tx.transaction else 'N/A'}")

        result = tx.result()
        print(f"[PASS] deploy_node_token() succeeded: {result}")
        return result
    except Exception as e:
        print(f"[FAIL] deploy_node_token() failed: {e}")
        traceback.print_exc()
        return None


def test_deploy_ipfs_token(collective, keypair):
    """Test deploying an IPFS token."""
    print("\n" + "="*60)
    print("TEST: Deploy IPFS Token (Write Operation)")
    print("="*60)

    name = "TestFile.txt"
    ipfs_hash = "QmTestHash123456789"
    file_type = "text/plain"
    gateways = "localhost:5001"
    ipns_hash = None

    try:
        print(f"Attempting to deploy IPFS token...")
        print(f"  name: {name}")
        print(f"  ipfs_hash: {ipfs_hash}")
        print(f"  file_type: {file_type}")
        print(f"  gateways: {gateways}")
        print(f"  ipns_hash: {ipns_hash}")

        tx = collective.deploy_ipfs_token(
            caller=keypair.public_key,
            name=_to_bytes(name),
            ipfs_hash=_to_bytes(ipfs_hash),
            file_type=_to_bytes(file_type),
            gateways=_to_bytes(gateways),
            ipns_hash=ipns_hash,
            source=keypair.public_key,
            signer=keypair
        )
        print(f"Transaction built, signing and submitting...")

        # Use sign_and_submit() to actually send to the network
        tx.sign_and_submit()

        print(f"Transaction submitted!")
        print(f"  Hash: {tx.transaction.hash_hex() if hasattr(tx, 'transaction') and tx.transaction else 'N/A'}")

        result = tx.result()
        print(f"[PASS] deploy_ipfs_token() succeeded: {result}")
        return result
    except Exception as e:
        print(f"[FAIL] deploy_ipfs_token() failed: {e}")
        traceback.print_exc()
        return None


def main():
    print("="*60)
    print("PINTHEON BINDING TEST SCRIPT")
    print("="*60)
    print(f"Soroban RPC: {SOROBAN_RPC_URL}")
    print(f"Network: {NETWORK_PASSPHRASE}")
    print(f"Collective Contract: {COLLECTIVE_ID}")
    print(f"Opus Contract: {OPUS_ID}")

    # Test connection
    if not test_connection():
        print("\n[ERROR] Cannot proceed - Soroban connection failed")
        return

    # Test keypair
    keypair = test_keypair()
    if not keypair:
        print("\n[ERROR] Cannot proceed - Keypair creation failed")
        return

    # Initialize clients
    print("\n" + "="*60)
    print("Initializing Contract Clients")
    print("="*60)

    try:
        collective = Collective(COLLECTIVE_ID, SOROBAN_RPC_URL, NETWORK_PASSPHRASE)
        print(f"[PASS] Collective client initialized")
    except Exception as e:
        print(f"[FAIL] Collective client failed: {e}")
        traceback.print_exc()
        return

    try:
        opus = Opus(OPUS_ID, SOROBAN_RPC_URL, NETWORK_PASSPHRASE)
        print(f"[PASS] Opus client initialized")
    except Exception as e:
        print(f"[FAIL] Opus client failed: {e}")
        traceback.print_exc()
        return

    # Run read-only tests
    collective_results = test_collective_read_only(collective, keypair)
    opus_results = test_opus_read_only(opus, keypair)

    # Summary of read-only tests
    print("\n" + "="*60)
    print("READ-ONLY TEST SUMMARY")
    print("="*60)

    print("\nCollective Contract:")
    for key, value in collective_results.items():
        status = "[PASS]" if value is not None else "[FAIL]"
        print(f"  {status} {key}: {value}")

    print("\nOpus Token Contract:")
    for key, value in opus_results.items():
        status = "[PASS]" if value is not None else "[FAIL]"
        print(f"  {status} {key}: {value}")

    # Check if user is already a member before trying write operations
    is_member = collective_results.get('is_member', False)

    print("\n" + "="*60)
    print("WRITE OPERATION TESTS")
    print("="*60)

    if not is_member:
        print(f"\nUser is NOT a member. Testing join()...")
        join_success = test_join_collective(collective, keypair)
        if not join_success:
            print("\n[WARN] Join failed - write operations may fail without membership")
    else:
        print(f"\nUser IS already a member. Skipping join()...")

    # Test deploy_node_token
    print("\nTesting deploy_node_token()...")
    node_result = test_deploy_node_token(collective, keypair)

    # Test deploy_ipfs_token
    print("\nTesting deploy_ipfs_token()...")
    ipfs_result = test_deploy_ipfs_token(collective, keypair)

    # Final summary
    print("\n" + "="*60)
    print("FINAL SUMMARY")
    print("="*60)
    print(f"Connection: [PASS]")
    print(f"Keypair: [PASS]")
    print(f"Read-only calls: {sum(1 for v in collective_results.values() if v is not None)}/{len(collective_results)} passed")
    print(f"Opus read-only: {sum(1 for v in opus_results.values() if v is not None)}/{len(opus_results)} passed")
    print(f"deploy_node_token: {'[PASS]' if node_result else '[FAIL]'}")
    print(f"deploy_ipfs_token: {'[PASS]' if ipfs_result else '[FAIL]'}")


if __name__ == "__main__":
    main()
