#!/usr/bin/python

import socket
import time

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
addr = ('127.0.0.1',2000)
sock.connect(addr)

while(True):
	time.sleep(2)

sock.close()
