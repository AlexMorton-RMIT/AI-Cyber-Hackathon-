# -*- coding: utf-8 -*-
"""
Created on Sat Nov  9 11:44:29 2024

@author: afvm3
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# Decrypt the message
def decrypt_message(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message.encode())
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()

    # Unpad the message to original form
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    return unpadded_message.decode()