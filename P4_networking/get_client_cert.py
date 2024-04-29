# Some imports that we think may be useful to you.
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
import socket
import ssl
import sys


def generate_or_load_private_key(
    filename: str = "private.pem",
) -> ed25519.Ed25519PrivateKey:
    try:
        return load_pem_private_key(open(filename, "rb").read(), password=None)
    except FileNotFoundError:
        pass
    private_key = ed25519.Ed25519PrivateKey.generate()
    open(filename, "wb").write(
        private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption(),
        )
    )
    return private_key


def get_public_bytes(priv: ed25519.Ed25519PrivateKey) -> bytes:
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo
    )


public_key = get_public_bytes(generate_or_load_private_key())
mdm_domain = sys.argv[1]
mdm_port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((mdm_domain, mdm_port))

context = ssl.create_default_context()
wrapped_sock = context.wrap_socket(sock, server_hostname=mdm_domain)

username = b"trelittl"
password = b"loving"
username_len = len(username).to_bytes(2, byteorder="big")
password_len = len(password).to_bytes(2, byteorder="big")
public_key_len = len(public_key).to_bytes(2, byteorder="big")
request_data = (
    username_len + username + password_len + password + public_key_len + public_key
)


wrapped_sock.sendall(request_data)
response_data = bytearray()

while True:
    chunk = wrapped_sock.recv(4096)

    if not chunk:
        break

    response_data.extend(chunk)

certificate_len = int.from_bytes(response_data[:2], byteorder="big")
certificate_chain = response_data[2 : 2 + certificate_len]

print(certificate_chain.decode())

wrapped_sock.close()
