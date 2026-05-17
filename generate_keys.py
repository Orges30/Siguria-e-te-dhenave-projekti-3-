"""
SSH Key Generation Utility
This module generates RSA key pairs for the SSH server and stores them securely.
It also generates Diffie-Hellman parameters for key exchange.
"""

import os
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.backends import default_backend
from datetime import datetime


def generate_rsa_keypair(key_size=2048):
    """
    Generate an RSA key pair for server authentication.
    
    Args:
        key_size (int): Size of the RSA key in bits (default: 2048)
    
    Returns:
        tuple: (private_key, public_key) - RSA key objects
    """
    print(f"[*] Generating RSA keypair ({key_size} bits)...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    print("[✓] RSA keypair generated successfully!")
    
    return private_key, public_key


def generate_dh_parameters(parameter_length=1024):
    """
    Generate Diffie-Hellman parameters for key exchange.
    
    Args:
        parameter_length (int): Length of DH parameters in bits (default: 1024)
    
    Returns:
        dh.DHParameters: DH parameter object
    """
    print(f"[*] Generating Diffie-Hellman parameters ({parameter_length} bits)...")
    print("[!] This may take a moment...")
    
    dh_params = dh.generate_parameters(
        generator=2,
        key_size=parameter_length,
        backend=default_backend()
    )
    
    print("[✓] Diffie-Hellman parameters generated successfully!")
    
    return dh_params


def serialize_private_key(private_key, password=None):
    """
    Serialize private key to PEM format.
    
    Args:
        private_key: RSA private key object
        password (bytes): Optional password for encryption
    
    Returns:
        str: PEM-formatted private key
    """
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()
    
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    
    return pem.decode('utf-8')


def serialize_public_key(public_key):
    """
    Serialize public key to PEM format.
    
    Args:
        public_key: RSA public key object
    
    Returns:
        str: PEM-formatted public key
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem.decode('utf-8')


def serialize_dh_parameters(dh_params):
    """
    Serialize DH parameters to PEM format.
    
    Args:
        dh_params: DH parameter object
    
    Returns:
        str: PEM-formatted DH parameters
    """
    pem = dh_params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    
    return pem.decode('utf-8')


def save_keys_to_file(private_key_pem, public_key_pem, dh_params_pem, filename='server_keys.json'):
    """
    Save generated keys to a JSON file.
    
    Args:
        private_key_pem (str): Private key in PEM format
        public_key_pem (str): Public key in PEM format
        dh_params_pem (str): DH parameters in PEM format
        filename (str): Output filename
    """
    keys_data = {
        "generation_timestamp": datetime.now().isoformat(),
        "key_type": "RSA-2048",
        "private_key": private_key_pem,
        "public_key": public_key_pem,
        "dh_parameters": dh_params_pem,
        "algorithm_support": {
            "key_exchange": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"],
            "encryption": ["aes-128-cbc", "aes-256-cbc"],
            "mac": ["hmac-sha1", "hmac-sha2-256"]
        }
    }
    
    with open(filename, 'w') as f:
        json.dump(keys_data, f, indent=4)
    
    print(f"[✓] Keys saved to {filename}")


def load_keys_from_file(filename='server_keys.json'):
    """
    Load keys from a JSON file.
    
    Args:
        filename (str): Input filename
    
    Returns:
        dict: Dictionary containing keys and parameters
    """
    with open(filename, 'r') as f:
        keys_data = json.load(f)
    
    print(f"[✓] Keys loaded from {filename}")
    return keys_data


def display_key_info(public_key_pem):
    """
    Display public key information.
    
    Args:
        public_key_pem (str): Public key in PEM format
    """
    print("\n" + "="*60)
    print("PUBLIC KEY FINGERPRINT")
    print("="*60)
    print(public_key_pem[:100] + "...")
    print("="*60 + "\n")


def main():
    """
    Main function to orchestrate key generation.
    """
    print("\n" + "="*60)
    print("SSH SERVER KEY GENERATION UTILITY")
    print("="*60 + "\n")
    
    try:
        # Generate RSA keypair
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        
        # Generate Diffie-Hellman parameters
        dh_params = generate_dh_parameters(parameter_length=1024)
        
        # Serialize keys
        print("\n[*] Serializing keys to PEM format...")
        private_key_pem = serialize_private_key(private_key)
        public_key_pem = serialize_public_key(public_key)
        dh_params_pem = serialize_dh_parameters(dh_params)
        print("[✓] Keys serialized successfully!")
        
        # Display public key info
        display_key_info(public_key_pem)
        
        # Save to file
        print("[*] Saving keys to file...")
        save_keys_to_file(private_key_pem, public_key_pem, dh_params_pem, 'server_keys.json')
        
        print("\n" + "="*60)
        print("[✓] KEY GENERATION COMPLETED SUCCESSFULLY")
        print("="*60)
        print("\nNext steps:")
        print("1. Update known_host.json with the public key")
        print("2. Start the SSH server with these keys")
        print("3. Connect with the SSH client\n")
        
    except Exception as e:
        print(f"\n[✗] Error during key generation: {str(e)}")
        raise


if __name__ == "__main__":
    main()
