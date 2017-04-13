#!/usr/bin/python
import os
import re
import sys
import time
import Queue
import errno
import socket
import select
import signal
import pickle
import random
import StringIO
import argparse
import threading

from datetime import datetime, date
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)


# Global varibles
# clientSockList -> Active client connections
# outputSockList -> Pending connections awaiting reply
# messageQueues  -> Queues for active client connections
# cookieMap      -> secret challenge bits of client cookie
keyMap = {}
nameMap = {}
cookieMap = {}
messageQueues = {}
clientSockList = []
outputSockList = []
clientPublicKeys = {}
clientListenPorts = {}
workerQueue = Queue.Queue()
queueLock = threading.Lock()

class workerThread(threading.Thread):

    def __init__(self, threadId, name):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self._is_shutdown = threading.Event()

    def run(self):
        try:
            while(True):
                if not processMessage(): break
                print self.name
        finally:
            self._is_shutdown.set()

    def shutdown(self):
        workerQueue.put(None)
        self._is_shutdown.wait()

def processMessage():
    queueLock.acquire()
    data = workerQueue.get()
    queueLock.release()
    if not data: return False
    MessageHandler(data[0],data[1])
    return True

# Receiver Thread class inherited from threading class
# Responsible for send/recv client messages
# _is_shutdown      -> Threading event flag used to block thread during
#                      shutdown do handle existing jobs before exiting
# _shutdown_request -> Flag used to exit while loop during shutdown
# run()             -> function invoked by thread.start()
# shutdown()        -> function for handling shutdown flags
class receiverThread(threading.Thread):

    def __init__(self, threadId, name, clientSockList):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
        self.clientSockList = clientSockList
        self._is_shutdown = threading.Event()
        self._shutdown_request = False

    def run(self):
        try:
            while not self._shutdown_request:
                receiveMessage()
        finally:
            self._shutdown_request = False
            self._is_shutdown.set()

    def shutdown(self):
        self._shutdown_request = True
        self._is_shutdown.wait()

# Receive Message function will poll for messages
# and read/write into respective message queues
# Called from receiver thread run() function
# rList, wList, eList -> socket objects for reading,
#                        writing, and error handling
def receiveMessage():
    pollTimeout = 2 #Just for testing purpose
    rList, wList, eList = select.select(clientSockList, outputSockList, clientSockList, pollTimeout)

    for s in rList:
        data = s.recv(1024)
        if data:
            workerQueue.put((s,data))
        else:
            if s in outputSockList:
                outputSockList.remove(s)
            if keyMap[s]: del keyMap[s]
            if nameMap[s]: del nameMap[s]
            clientSockList.remove(s)
            s.close()
            print "Client removed,", len(clientSockList), "active clients"
            del messageQueues[s]

    for s in wList:
        try:
            nextMsg = messageQueues[s].get_nowait()
        except Queue.Empty:
            outputSockList.remove(s)
        else:
            s.send(nextMsg)

    for s in eList:
        clientSockList.remove(s)
        print "Client removed,", len(clientSockList), "active clients"
        if s in outputSockList:
            outputSockList.remove(s)
        s.close()
        del messageQueues[s]

# Tcp Server class, Responsible for listening and accepting client connections
# serverAddress    -> address received from commandline arguments
# MessageHandler   -> class that processes the request
# serverBind()     -> bind the address to the socket
# SO_REUSEADDR     -> flag to re-use same address when socket in TIME_WAIT state
# serverActivate() -> start listening for client connections
# serverAccept()   -> accept incoming client connections
# setblocking(0)   -> make socket non-blocking for asynchronous message handling
# serverClose()    -> close the server socket
class TcpServer:

    def __init__(self, serverAddress, MessageHandler):
        self.serverAddress = serverAddress
        self.MessageHandler = MessageHandler
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.serverBind()
            self.serverActivate()
        except Exception in e:
            print e
            self.serverClose()
            sys.exit(1)

    def serverBind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.serverAddress)
        self.serverAddress = self.socket.getsockname()

    def serverActivate(self):
        self.socket.listen(5)

    def serverAccept(self):
        try:
            conn, addr = self.socket.accept()
            conn.send(challengeCookie(addr).cookie)
        except socket.error:
            return
        conn.setblocking(0)
        clientSockList.append(conn)
        messageQueues[conn] = Queue.Queue()
        keyMap[conn] = ''
        nameMap[conn] = ''
        print "New client added,", len(clientSockList), "active clients"

    def serverClose(self):
        self.socket.close()

# Challenge Cookie class
# Responsible for generating challenge cookie
# 128 bit cookie hash along with 118 bit cookie is sent while
# accepting connection, last 10 bits of cookie has to be
# calculated by client through brute force thus reducing DOS attacks
class challengeCookie:

    def __init__(self, clientAddress):
        self.clientAddress = clientAddress
        self.cookie = self.generateCookie()

    def generateCookie(self):
        bits = bin(random.getrandbits(128))
        bits128 = str(bits[2:130]).rjust(128,'1')
        challenge = bits128 + self.clientAddress[0]
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(challenge)
        clientBits, secretBits = bits128[0:118], bits128[118:128]
        cookieMap[self.clientAddress] = secretBits
        return clientBits + '<<>>' + digest.finalize()

# Verify last 10 bits of challenge sent while accepting connection
def verifyCookie(clientConn, cookieResponse):
    return cookieResponse == cookieMap[clientConn.getpeername()]

# RSA Encryption
def RSAEncryption(client_public_key, symmetricKey):
    try:
        buf = StringIO.StringIO(client_public_key)
        destinationPublicKey = serialization.load_pem_public_key(
                            buf.read(),backend = default_backend())

        return destinationPublicKey.encrypt(symmetricKey,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),label=None))
    except:
        print "encryption failed!!"
        raise

# RSA Decrytion to decrypt the keys
def RSADecryption(cipherKey):
    return serverPrivateKey.decrypt(cipherKey,padding.OAEP(
                     mgf=padding.MGF1(algorithm=hashes.SHA1()),
                     algorithm=hashes.SHA1(),label=None))

# Encrypting the text using AES algorithm
def encryptDataWithAESGCM(symmetricKey, data, authenticationString):
    iv = os.urandom(32)
    encryptor = Cipher(algorithms.AES(symmetricKey),modes.GCM(iv),backend=default_backend()).encryptor()
    encryptor.authenticate_additional_data(authenticationString)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

# Decrypt the data with AES and GCM algorithm
def decryptDataWithAES(decryptedKey,authenticationString,iv,cipherText,encryptorTag):
    decryptor = Cipher(algorithms.AES(decryptedKey),modes.GCM(iv, encryptorTag),backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(authenticationString)
    return decryptor.update(cipherText) + decryptor.finalize()

#verify client password hash with server DB hash
def verifyHashSaltPassword(password, userName):
    try:
        PasswordFile = open("PasswordDB.txt", "rb")
        with PasswordFile as PasswordFromFile:
            lines = PasswordFromFile.readlines()
            for line in lines:
                line = line.rstrip('\n')
                if re.match(userName, line):
                    user, salt, hashValue = line.split(':', 2)
    except:
        print "Error in accessing the Password file"
        return False
    return True
    #return password == hashValue

#verifyTimeStamp with client time stamp and if difference is more than a minute drop the message
def verifyTimeStamp(clientTimeStamp):
    fmt = '%Y-%m-%d %H:%M:%S'
    serverTimeStamp = datetime.now().strftime(fmt)
    clientTimeStamp = datetime.strptime(clientTimeStamp, fmt)
    serverTimeStamp = datetime.strptime(serverTimeStamp, fmt)
    daysDiff = (serverTimeStamp - clientTimeStamp).days
    # convert days into minutes
    minutesDiff = daysDiff * 24 * 60
    if (minutesDiff > 1):
        return False
    return True

#generate current time stamp
def generateCurrentTime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def obtainSymmKey(request):
    cipherKey = request.split('<<>>')[4]
    return RSADecryption(cipherKey)

def decryptData(client, request):
    parts = request.split('<<>>')
    iv, cipherText, encryptorTag, authenticationString = parts[0], parts[1], parts[2], parts[3]
    return decryptDataWithAES(keyMap[client],authenticationString,iv,cipherText,encryptorTag)

# Message Handler class. Responsible for processing the client message
class MessageHandler:

    def __init__(self, client, request):
        self.client = client
        self.request = request
        try:
            self.setup()
        except:
            print "Invalid Message"
            raise
            return
        self.processRequest()

    def setup(self):
        if keyMap[self.client] == '':
            keyMap[self.client] = obtainSymmKey(self.request)
        self.decryptedData = decryptData(self.client, self.request)

    def processRequest(self):
        try:
            data = pickle.loads(self.decryptedData)
        except:
            print "Deserializing Error, Dropping Packet from", self.client.getpeername()
            return
        msgType = data[0]

        if msgType == 'LOGIN1':
            if not processLoginMsg1(self, data):
                return
            self.encryptData()
            self.sendResponse()

        elif msgType == 'LOGIN2':
            if not processLoginMsg2(self, data):
                return
            self.encryptData()
            cipherKey = RSAEncryption(clientPublicKeys[self.client], keyMap[self.client])
            self.dataToBeSentToClient = self.dataToBeSentToClient + '<<>>' + cipherKey
            self.sendResponse()

        elif msgType == 'LOGIN3':
            self.clientTS, clientListenPorts[self.client] = data[1], data[2]
            if not verifyTimeStamp(self.clientTS):
                print "Found Replay attack, Dropping packet from", self.getpeername()
                return
            self.dataToBeSentToClient = "You are now logged In!!"
            self.sendResponse()

    def encryptData(self):
        authenticationString = b"ChatApp"
        iv, cipherText, encryptorTag = encryptDataWithAESGCM(keyMap[self.client], self.data, authenticationString)
        self.dataToBeSentToClient = iv + '<<>>' + cipherText + '<<>>' + encryptorTag + '<<>>' + authenticationString

    def sendResponse(self):
        outputSockList.append(self.client)
        messageQueues[self.client].put(self.dataToBeSentToClient)

def processLoginMsg1(msgObj, data):
    chalResp, userName, msgObj.clientTS = data[1], data[2], data[3]
    if not verifyTimeStamp(msgObj.clientTS):
        print "Found Replay attack, Dropping packet from", msgObj.getpeername()
        return False
    if not verifyCookie(msgObj.client, chalResp[0:10]):
        print "Challenge Response failed, Dropping Packet from", msgObj.getpeername()
        return False
    try:
        PasswordFile = open("PasswordDB.txt", "rb")
        with PasswordFile as PasswordFromFile:
            lines = PasswordFromFile.readlines()
            for line in lines:
                line = line.rstrip('\n')
                if re.match(userName, line):
                    msgObj.user, msgObj.salt, msgObj.hashValue = line.split(':', 2)
    except:
        print "Error in accessing the Password file"
        return False
    nameMap[msgObj.client] = userName #!TODO Multiple logins case shud be handled
    serverTimeStampToClient = generateCurrentTime()
    dataToSend = (msgObj.salt, msgObj.user, msgObj.clientTS, serverTimeStampToClient)
    msgObj.data = pickle.dumps(dataToSend)
    return True

def processLoginMsg2(msgObj, data):
    password, userName, msgObj.clientTS, clientPublicKeys[msgObj.client] = data[1], data[2], data[3], data[4]
    if not verifyTimeStamp(msgObj.clientTS):
        print "Found Replay attack, Dropping packet from", msgObj.getpeername()
        return False
    if not verifyHashSaltPassword(password, userName):
        msgObj.dataToBeSentToClient = "LOGIN FAILED"
        msgObj.sendResponse()
        return False
    print "User password Authenticated!!"
    #destroy old symmetri key we used for previous messages and generate new shared key
    keyMap[msgObj.client] = os.urandom(32) #AES 256
    serverTimeStampToClient = generateCurrentTime()
    dataToSend = (userName, msgObj.clientTS, serverTimeStampToClient)
    msgObj.data = pickle.dumps(dataToSend)
    return True

# Signal handler for SIGTERM and SIGINT
def signal_handler (signal, frame):
    print "Signal Received for Shutdown, Cleaning Up..."
    cleanup()

# CleanUp before exiting. Wait for threads to finish jobs and close socket
def cleanup():
    rThread.shutdown()
    rThread.join()
    wThread.shutdown()
    wThread.join()
    serverSock.serverClose()
    print "Shutting down server..."
    sys.exit(0)

# Read arguments
def parser():
    # Parser to read the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', '--server_port', type=int,  required='True', help="Server Port to Bind")

    # Parse the arguments and check for validity
    args = parser.parse_args()
    if args.server_port < 1024 or args.server_port > 65535:
        print "Invalid Port... Port Range [1024-65535]"
        sys.exit(1)

    # Read the Keys from files
    global serverPublicKey
    global serverPrivateKey
    try:
        # Read Destination Publick Key and serialize into bytes
        serverPublicKeyFile = open("server_public_key.der", "rb")
        with serverPublicKeyFile as publicKey:
            serverPublicKey = serialization.load_der_public_key(
                                publicKey.read(),backend = default_backend())

        # Read Sender's private key and serialize into bytes
        serverPrivateKeyFile = open("server_private_key.der", "rb")
        with serverPrivateKeyFile as privateKey:
            serverPrivateKey = serialization.load_der_private_key(
                                privateKey.read(),password = None,
                                backend = default_backend())
    except:
        print "Error in Reading RSA Keys"
        sys.exit(1)

    serverAddress = ('',args.server_port)
    return serverAddress

# Main thread handles shutdown and inturrupt signals along with accepting
# client connections and updating client socket list
def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    print "Server started, waiting for clients.."
    while(True):
        serverSock.serverAccept()

# Program start
# serverSock -> TcpServer object
# rThread    -> Receiver Thread object
if __name__ == "__main__":
    serverAddress = parser()
    serverSock = TcpServer(serverAddress, MessageHandler)
    rThread = receiverThread(1, "Receiver Thread", clientSockList)
    wThread = workerThread(2, "Worker 1")
    wThread.start()
    rThread.start()
    main()
    cleanup()
