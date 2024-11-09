# -*- coding: utf-8 -*-
"""
Created on Sat Nov  9 11:52:56 2024

@author: afvm3
"""
from cryptography.hazmat.primitives.asymmetric import rsa 
from cryptography.hazmat.primitives import serialization
import random

def main(): 
    length = random.randint(1,10)
    characters = "qwertyuiopasdfghjklzxcvbnm1234567890"
    Password = ''.join(random.choices(characters, k=length))
    Create_RSA_keys(Password)


def Create_RSA_keys(Password):

    Password = bytes(Password, 'utf-8')

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,)
    
    public_key = private_key.public_key()
    
    
    private_key_pass = Password
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
    )
    
    #create private key pem file
    with open("private_key.pem", "wb") as f:
        f.write(pem_private_key)
        
        
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    #create public key pem file
    with open("public_key.pem", "wb") as f:
        f.write(pem_public_key)

#run main
main()