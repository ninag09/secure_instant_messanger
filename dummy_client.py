#!/usr/bin/python

import socket
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
addr = ('127.0.0.1',2000)
sock.connect(addr)

def hashm(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message)
    hash_of_message = digest.finalize()
    return hash_of_message

def break_challenge(bits_118, hash_of_challenge):
	for i in xrange(0,1024):
		iterator = str(bin(i)[2:12]).rjust(10,'0')
		if(hashm(bits_118+iterator+'127.0.0.1') == hash_of_challenge):
			challenge_response = iterator
			break
	return challenge_response

while(True):
	data = sock.recv(1024)
	bits, challenge = data.split('<<>>',1)
	response = break_challenge(bits, challenge)
	sock.send(response) # For successful verification
	#sock.send(data)
	time.sleep(2)

sock.close()
