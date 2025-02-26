#!/usr/bin/env python3
#just in case
import base64
import hashlib
import os
#crypt imports
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
#app imports
from flask import Flask, request

app = Flask(__name__)
app.config["DEBUG"] = True
SALT = os.urandom(16)

class EndpointCipher:
    def __init__(self, password, salt):
        self.password = password.encode()
        self.salt = salt

    def encode(self,message):
        #AES encryption
        #derive encryption key from password using PBKDF2
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        iterations=10000,
                        salt = self.salt,
                        length=32,
                        backend=default_backend()
                        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        #Encrypt the message using the derived key
        f = Fernet(key)
        return f.encrypt(message.encode())

    def decode(self, message):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                        iterations=10000,
                        salt = self.salt,
                        length=32,
                        backend=default_backend()
                        )

        #Decrypt
        key = base64.urlsafe_b64encode(kdf.derive(self.password.encode()))
        f = Fernet(key)
        return f.decrypt(message.encode()).decode()

@app.route("/encode", methods=["POST"])
def encode():
    password = request.form.get("password")
    message = request.form.get("message")
    salt = os.urandom(16)
    cipher = EndpointCipher(password, salt)
    encoded_message = cipher.encode(message)
    return {"salt": base64.urlsafe_b64encode(salt).decode(), "message": encoded_message.decode()}

@app.route("/decode", methods=["POST"])
def decode():
    password = request.form.get("password")
    salt = base64.urlsafe_b64decode(request.form.get("salt")).encode()
    message = request.form.get("message")

    cipher = EndpointCipher(password, salt)
    decrypted_message = cipher.decode(message.encode())
    return decrypted_message


if __name__ == "__main__":
    app.run()
