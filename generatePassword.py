#!/usr/bin/env python
import os
import sys
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def hashSaltPassword(username, password):

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
        backend = default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    PasswordFile = open("PasswordDB.txt", "a+")
    PasswordFile.write(username + "<<>>" + salt + "<<>>" + key)
    PasswordFile.write('\n')

if __name__ == "__main__":

    if(len(sys.argv) < 2) :
        print 'Usage: python generatePassword.py username password'
        sys.exit(1)

    hashSaltPassword(sys.argv[1], sys.argv[2])

