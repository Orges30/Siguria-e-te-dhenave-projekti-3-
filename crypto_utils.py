import base64
import hashlib
import hmac

from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def create_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def save_private_key(private_key, filename):
    key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(filename, "wb") as file:
        file.write(key_bytes)


def save_public_key(public_key, filename):
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(filename, "wb") as file:
        file.write(key_bytes)


def load_private_key(filename):
    with open(filename, "rb") as file:
        return serialization.load_pem_private_key(
            file.read(),
            password=None
        )


def load_public_key_from_bytes(key_bytes):
    return serialization.load_pem_public_key(key_bytes)


def public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
def dh_public_key_to_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def get_fingerprint(public_key_bytes):
    hash_value = hashlib.sha256(public_key_bytes).digest()
    return base64.b64encode(hash_value).decode()


def sign_message(private_key, message):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except Exception:
        return False


def create_dh_parameters():
    return dh.generate_parameters(
        generator=2,
        key_size=1024
    )


def create_dh_keys(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    return private_key, public_key


def dh_parameters_to_bytes(parameters):
    return parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )


def load_dh_parameters(parameter_bytes):
    return serialization.load_pem_parameters(parameter_bytes)


def create_session_keys(my_private_key, other_public_key):
    shared_secret = my_private_key.exchange(other_public_key)

    final_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"simple ssh handshake"
    ).derive(shared_secret)

    encryption_key = final_key[:32]
    hmac_key = final_key[32:]

    return encryption_key, hmac_key


def create_hmac(hmac_key, message):
    return hmac.new(hmac_key, message, hashlib.sha256).hexdigest()


def check_hmac(hmac_key, message, received_hmac):
    expected_hmac = create_hmac(hmac_key, message)
    return hmac.compare_digest(expected_hmac, received_hmac)