import socket
import pickle
import json
import logging

from crypto_utils import *

HOST = "127.0.0.1"
PORT = 5000

KNOWN_HOSTS_FILE = "known_hosts.json"

CLIENT_ALGORITHMS = {
    "key_exchange": ["Diffie-Hellman"],
    "encryption": ["AES256"],
    "mac": ["HMAC-SHA256"]
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(message)s"
)


def load_known_hosts():
    with open(KNOWN_HOSTS_FILE, "r") as file:
        return json.load(file)


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    logging.info("Welcome to Simplified SSH Client.")
    logging.info("Attempting to connect to the SSH server...")

    client_socket.connect((HOST, PORT))

    logging.info("Connected to server.")
    logging.info("Starting handshake protocol...")

    
    client_socket.send(pickle.dumps(CLIENT_ALGORITHMS))

    selected_algorithms = pickle.loads(client_socket.recv(4096))

    if selected_algorithms == b"ALGORITHM_ERROR":
        raise Exception("Algorithm negotiation failed.")

    logging.info(f"Server selected algorithms: {selected_algorithms}")

    server_data = pickle.loads(client_socket.recv(16384))

    server_public_key_bytes = server_data["server_public_key"]
    server_dh_public_key_bytes = server_data["server_dh_public_key"]
    signature = server_data["signature"]
    dh_parameters_bytes = server_data["dh_parameters"]

    logging.info("Server authentication data received.")

    known_hosts = load_known_hosts()

    if HOST not in known_hosts:
        raise Exception("Unknown host. Connection stopped.")

    if not known_hosts[HOST]["trusted"]:
        raise Exception("Host is not trusted.")

    expected_fingerprint = known_hosts[HOST]["fingerprint"]
    actual_fingerprint = get_fingerprint(server_public_key_bytes)

    if expected_fingerprint != actual_fingerprint:
        raise Exception("Server fingerprint does not match. Possible MITM attack.")

    logging.info("Server fingerprint verified.")

    server_public_key = load_public_key_from_bytes(server_public_key_bytes)

    signature_is_valid = verify_signature(
        server_public_key,
        signature,
        server_dh_public_key_bytes
    )

    if not signature_is_valid:
        raise Exception("Server signature is invalid.")

    logging.info("Server identity verified.")

    dh_parameters = load_dh_parameters(dh_parameters_bytes)

    client_dh_private_key, client_dh_public_key = create_dh_keys(dh_parameters)
    client_dh_public_key_bytes = public_key_to_bytes(client_dh_public_key)

    client_socket.send(client_dh_public_key_bytes)

    logging.info("Client Diffie-Hellman public key sent.")

    server_dh_public_key = load_public_key_from_bytes(server_dh_public_key_bytes)

    encryption_key, hmac_key = create_session_keys(
        client_dh_private_key,
        server_dh_public_key
    )

    logging.info("Session keys generated.")
    logging.info(f"Encryption key: {encryption_key.hex()}")
    logging.info(f"HMAC key: {hmac_key.hex()}")

    final_response = pickle.loads(client_socket.recv(4096))

    message = final_response["message"]
    received_hmac = final_response["hmac"]

    if not check_hmac(hmac_key, message, received_hmac):
        raise Exception("HMAC verification failed.")

    if message == b"HANDSHAKE_SUCCESS":
        logging.info("Server identity verified. Handshake successful.")
        logging.info("Secure channel established.")
        logging.info("You can now begin your session.")

except Exception as error:
    logging.error(f"Handshake failed: {error}")

finally:
    client_socket.close()
    logging.info("Connection closed.")