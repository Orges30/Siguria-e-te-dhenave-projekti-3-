import json

from crypto_utils import (
    create_rsa_keys,
    save_private_key,
    save_public_key,
    public_key_to_bytes,
    get_fingerprint
)

SERVER_PRIVATE_KEY_FILE = "server_private_key.pem"
SERVER_PUBLIC_KEY_FILE = "server_public_key.pem"
KNOWN_HOSTS_FILE = "known_hosts.json"

SERVER_HOST = "127.0.0.1"

private_key, public_key = create_rsa_keys()

save_private_key(private_key, SERVER_PRIVATE_KEY_FILE)
save_public_key(public_key, SERVER_PUBLIC_KEY_FILE)

public_key_bytes = public_key_to_bytes(public_key)
fingerprint = get_fingerprint(public_key_bytes)

known_hosts = {
    SERVER_HOST: {
        "server_name": "Local SSH Server",
        "trusted": True,
        "fingerprint": fingerprint
    }
}

with open(KNOWN_HOSTS_FILE, "w") as file:
    json.dump(known_hosts, file, indent=4)

print("Keys were generated successfully.")
print("known_hosts.json was created.")
print("Server fingerprint:")
print(fingerprint)