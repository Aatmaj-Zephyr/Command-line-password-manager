import argparse
import base64
import hashlib
import random
import string
import pyperclip
import json
from cryptography.fernet import Fernet

def encrypt_data(data, key):
    #Encrypt data using the provided key.
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()


def generate_key(master):
    # Generate a Fernet key using the provided master key.
    # symmetric cipher
    # Convert the master key to bytes
    master_bytes = master.encode()
    
    # Use SHA-256 hash of the master key as the key for Fernet
    hashed_key = hashlib.sha256(master_bytes).digest()
    
    # Fernet keys are required to be 32 url-safe base64-encoded bytes
    return base64.urlsafe_b64encode(hashed_key)

key = generate_key("erg")

for i in range(10):
    print(encrypt_data("data", key))