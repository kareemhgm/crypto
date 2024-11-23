import socket
import ssl
from os import urandom
from tkinter import filedialog, Tk
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Load server's public key
def load_public_key():
    with open("server_public_key.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

# Encrypt AES key using RSA
def encrypt_aes_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Encrypt file using AES
def encrypt_file(file_path, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(file_path, "rb") as f:
        file_data = f.read()
    return encryptor.update(file_data) + encryptor.finalize()

# GUI file selection
def select_file():
    root = Tk()
    root.withdraw()
    return filedialog.askopenfilename()

# Main client functionality
def send_file():
    public_key = load_public_key()
    aes_key = urandom(32)
    iv = urandom(16)

    file_path = select_file()
    if not file_path:
        print("[Client] No file selected.")
        return

    encrypted_data = encrypt_file(file_path, aes_key, iv)
    enc_aes_key = encrypt_aes_key(aes_key, public_key)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("server_cert.pem")

    with socket.create_connection(('127.0.0.1', 65432)) as sock:
        with context.wrap_socket(sock, server_hostname="localhost") as ssock:
            print("[Client] Connected to the server.")

            ssock.sendall(enc_aes_key)
            print("[Client] AES key sent.")

            ssock.sendall(iv)
            ssock.sendall(encrypted_data)
            print("[Client] File sent securely.")

if __name__ == "__main__":
    send_file()
