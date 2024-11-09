# -*- coding: utf-8 -*-
"""
Created on Sat Nov  9 10:59:44 2024

@author: afvm3
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# Generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

# Encrypt the message
def encrypt_message(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Padding the message to match block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and encrypted message, both base64-encoded
    return base64.b64encode(iv + encrypted_message).decode()



# Example usage
password = "final_year_MIT_student"
salt = os.urandom(16)
message = "Welcome to RMIT GenAI and Cyber Security Hackathon"

# Generate key
key = generate_key(password, salt)

assert key is not None