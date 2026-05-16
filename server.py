import socket
import pickle
import logging

from crypto_utils import *

HOST = "127.0.0.1"
PORT = 5000

SERVER_PRIVATE_KEY_FILE = "server_private_key.pem"

SERVER_ALGORITHMS = {
    "key_exchange": "Diffie-Hellman",
    "encryption": "AES256",
    "mac": "HMAC-SHA256"
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(message)s"
)


def algorithms_match(client_algorithms):
    for category in SERVER_ALGORITHMS:
        if SERVER_ALGORITHMS[category] not in client_algorithms[category]:
            return False

    return True


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    logging.info("Server starting up...")

    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    logging.info("Awaiting client connections...")

    connection, address = server_socket.accept()

    logging.info(f"Client connected from {address}")
    logging.info("Starting handshake...")


    client_algorithms = pickle.loads(connection.recv(4096))

    logging.info("Client algorithms received.")

    if not algorithms_match(client_algorithms):
        connection.send(b"ALGORITHM_ERROR")
        raise Exception("No matching algorithms.")

    connection.send(pickle.dumps(SERVER_ALGORITHMS))

    logging.info("Algorithm negotiation successful.")

    server_private_key = load_private_key(SERVER_PRIVATE_KEY_FILE)
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = public_key_to_bytes(server_public_key)

    logging.info("Server RSA key loaded.")


    dh_parameters = create_dh_parameters()
    server_dh_private_key, server_dh_public_key = create_dh_keys(dh_parameters)

    server_dh_public_key_bytes = public_key_to_bytes(server_dh_public_key)

    logging.info("Server Diffie-Hellman key created.")

    signature = sign_message(
        server_private_key,
        server_dh_public_key_bytes
    )

    logging.info("Server signed its Diffie-Hellman key.")

    data_for_client = {
        "server_public_key": server_public_key_bytes,
        "server_dh_public_key": server_dh_public_key_bytes,
        "signature": signature,
        "dh_parameters": dh_parameters_to_bytes(dh_parameters)
    }

    connection.send(pickle.dumps(data_for_client))

    logging.info("Server authentication data sent to client.")

    client_dh_public_key_bytes = connection.recv(8192)
    client_dh_public_key = load_public_key_from_bytes(client_dh_public_key_bytes)

    logging.info("Client Diffie-Hellman key received.")


    encryption_key, hmac_key = create_session_keys(
        server_dh_private_key,
        client_dh_public_key
    )

    logging.info("Session keys generated.")
    logging.info(f"Encryption key: {encryption_key.hex()}")
    logging.info(f"HMAC key: {hmac_key.hex()}")

    message = b"HANDSHAKE_SUCCESS"
    message_hmac = create_hmac(hmac_key, message)

    final_response = {
        "message": message,
        "hmac": message_hmac
    }

    connection.send(pickle.dumps(final_response))

    logging.info("Handshake successful.")
    logging.info("Secure channel established.")

except Exception as error:
    logging.error(f"Handshake failed: {error}")

finally:
    server_socket.close()
    logging.info("Server closed.")