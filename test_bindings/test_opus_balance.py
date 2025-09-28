#!/usr/bin/env python3
"""
Test script to verify OPUS token balance functionality.
"""
import os
import sys
from stellar_sdk import Keypair, Network
from opus_bindings import Client as Opus
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constants
TESTNET_SECRET = os.getenv("TESTNET_SECRET", "SATCSJPFRLVMX2IHPECYET4XEFM2M76P25OKFAG2HMFUUFIPNBIVXF2Q")
TESTNET_SOROBAN_SERVER = "https://soroban-testnet.stellar.org"
NETWORK_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
OPUS_CONTRACT_ID = "CDUGFWQQAUUAMEIHVKMIZB6H3TDDA3LKM24NJ7VFOWRC2DJZVH3WUUQ3"

def get_opus_balance():
    """Test getting OPUS token balance."""
    try:
        # Initialize keypair from secret
        keypair = Keypair.from_secret(TESTNET_SECRET)
        print(f"Using account: {keypair.public_key}")
        
        # Initialize OPUS token client
        opus = Opus(OPUS_CONTRACT_ID, TESTNET_SOROBAN_SERVER, NETWORK_PASSPHRASE)
        print(f"Initialized OPUS token client with contract ID: {OPUS_CONTRACT_ID}")
        
        # Get balance
        print("\n=== Getting OPUS balance ===")
        from stellar_sdk import Address
        address = Address(keypair.public_key)
        balance_tx = opus.balance(address)
        print(f"Balance transaction prepared: {balance_tx}")
        
        # Simulate the transaction first
        print("\n=== Simulating transaction ===")
        simulate_result = balance_tx.simulate()
        print(f"Simulation result: {simulate_result}")
        
        # Get the actual balance
        print("\n=== Getting balance result ===")
        balance = balance_tx.result()
        print(f"OPUS Balance: {balance} stroops")
        
        # Convert to XLM (1 XLM = 10,000,000 stroops)
        xlm_balance = int(balance) / 10_000_000
        print(f"OPUS Balance: {xlm_balance} XLM")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("=== Testing OPUS Token Balance ===")
    success = get_opus_balance()
    
    if success:
        print("\n✅ OPUS balance check completed successfully!")
    else:
        print("\n❌ OPUS balance check failed.")
        sys.exit(1)
