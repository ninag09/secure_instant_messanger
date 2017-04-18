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
# activeUserlist -> active username list
# clientConnMap  -> Map storing client connection objects
# userConnMap    -> Map with username as key
# workerQueue    -> Queue that can be shared between worker threads
#                   free worker threads can pick up message and process
userConnMap = {}
clientConnMap = {}
clientSockList = []
outputSockList = []
activeUserlist = []
workerQueue = Queue.Queue()
queueLock = threading.Lock()

# class clientConn
# Responsible for storing client details
# An object is created for each client connection
# and it is deleted when the connection with that user is terminated
class clientConn:
    def __init__(self, sock, messageQueue=None, cookie=None, userName=None,
                key=None, publicKey=None, clientIpPort=None):
        self.sockObj = sock
        self.messageQueue = messageQueue
        self.cookie = cookie
        self.userName = userName
        self.key = key
        self.publicKey = publicKey
        self.clientIpPort = clientIpPort
        self.authenticated = False

    def printValues(self, detailed=False):
        print "Connection From IP :", self.sockObj.getpeername()[0], ', Port :', self.sockObj.getpeername()[1]
        print "Username :", self.userName
        print "User listening on IP :", self.clientIpPort[0], ', Port :', self.clientIpPort[1]
        if not detailed: return
        print "Secret cookie :", self.cookie
        print "User Public Key :", self.publicKey

# class workerThread
# Responsible for processing the clients messages
# Worker threads are implemented to support scalability
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

    def __init__(self, threadId, name):
        threading.Thread.__init__(self)
        self.threadId = threadId
        self.name = name
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
    pollTimeout = 0.1
    rList, wList, eList = select.select(clientSockList, outputSockList, clientSockList, pollTimeout)

    for s in rList:
        try:
            data = s.recv(1024)
        except:
            continue
        if data:
            workerQueue.put((s,data))
        else:
            if s in outputSockList:
                outputSockList.remove(s)
            clientSockList.remove(s)
            if clientConnMap[s].userName in activeUserlist:
                if clientConnMap[s].authenticated:
                    print clientConnMap[s].userName, "logged out,", len(clientSockList), "active clients"
                activeUserlist.remove(clientConnMap[s].userName)
                del userConnMap[clientConnMap[s].userName]
            s.close()
            del clientConnMap[s]

    for s in wList:
        try:
            nextMsg = clientConnMap[s].messageQueue.get_nowait()
        except Queue.Empty:
            outputSockList.remove(s)
        else:
            s.send(nextMsg)

    for s in eList:
        clientSockList.remove(s)
        if clientConnMap[s].userName in activeUserlist:
            activeUserlist.remove(clientConnMap[s].userName)
            del userConnMap[clientConnMap[s].userName]
        print "Client removed,", len(clientSockList), "active clients"
        if s in outputSockList:
            outputSockList.remove(s)
        s.close()
        del clientConnMap[s]

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

    def __init__(self, serverAddress):
        self.serverAddress = serverAddress
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
        except socket.error:
            return
        conn.setblocking(0)
        clientSockList.append(conn)
        clientConnMap[conn] = clientConn(conn)
        clientConnMap[conn].messageQueue = Queue.Queue()
        conn.send(challengeCookie(addr,conn).cookie)

    def serverClose(self):
        self.socket.close()

# Challenge Cookie class
# Responsible for generating challenge cookie
# 128 bit cookie hash along with 118 bit cookie is sent while
# accepting connection, last 10 bits of cookie has to be
# calculated by client through brute force thus reducing DOS attacks
class challengeCookie:

    def __init__(self, clientAddress, conn):
        self.clientAddress = clientAddress
        self.conn = conn
        self.cookie = self.generateCookie()

    def generateCookie(self):
        bits = bin(random.getrandbits(128))
        bits128 = str(bits[2:130]).rjust(128,'1')
        challenge = bits128 + self.clientAddress[0]
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(challenge)
        clientBits, secretBits = bits128[0:118], bits128[118:128]
        clientConnMap[self.conn].cookie = secretBits
        return clientBits + '<<>>' + digest.finalize()

# Verify last 10 bits of challenge sent while accepting connection
def verifyCookie(clientConn, cookieResponse):
    return cookieResponse == clientConnMap[clientConn].cookie

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

# RSA Decrytion to decrypt the keys
def RSADecryption(cipherKey):
    return serverPrivateKey.decrypt(cipherKey,padding.OAEP(
                     mgf=padding.MGF1(algorithm=hashes.SHA1()),
                     algorithm=hashes.SHA1(),label=None))

# Encrypting the text using AES algorithm
def encryptDataWithAESGCM(symmetricKey, data):
    iv = os.urandom(32)
    encryptor = Cipher(algorithms.AES(symmetricKey),modes.GCM(iv),backend=default_backend()).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

# Decrypt the data with AES and GCM algorithm
def decryptDataWithAES(decryptedKey,iv,cipherText,encryptorTag):
    decryptor = Cipher(algorithms.AES(decryptedKey),modes.GCM(iv, encryptorTag),backend=default_backend()).decryptor()
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
                    user, salt, hashValue = line.split('<<>>', 2)
    except:
        print "Error in accessing the Password file"
        return False
    return password == hashValue

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

# Obtain Symmetric Key from cipherKey
def obtainSymmKey(request):
    cipherKey = request.split('<<>>')[3]
    return RSADecryption(cipherKey)

# Decrypt Data using AES
def decryptData(client, request):
    parts = request.split('<<>>')
    iv, cipherText, encryptorTag = parts[0], parts[1], parts[2]
    return decryptDataWithAES(clientConnMap[client].key, iv,cipherText,encryptorTag)

# Message Handler class. Responsible for processing the client message
class MessageHandler:

    def __init__(self, client, request):
        self.client = client
        self.request = request
        try:
            self.setup()
        except:
            print "Invalid Message"
            return
        self.processRequest()

    def setup(self):
        if clientConnMap[self.client].key == None:
            clientConnMap[self.client].key = obtainSymmKey(self.request)
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
            cipherKey = RSAEncryption(clientConnMap[self.client].publicKey, clientConnMap[self.client].key)
            self.dataToBeSentToClient = self.dataToBeSentToClient + '<<>>' + cipherKey
            self.sendResponse()

        elif msgType == 'LOGIN3':
            self.clientTS, clientConnMap[self.client].clientIpPort = data[1], data[2]
            if not verifyTimeStamp(self.clientTS):
                print "Found Replay attack, Dropping packet from", self.getpeername()
                return
            self.data = "You are now logged In!!"
            self.encryptData()
            self.sendResponse()
            clientConnMap[self.client].printValues()
            print

        elif msgType == "LIST":
            self.clientTS, user = data[1], data[2]
            if not verifyTimeStamp(self.clientTS):
                print "Found Replay attack, Dropping packet from", self.getpeername()
                return
            data = ('LIST', self.clientTS, activeUserlist)
            self.data = pickle.dumps(data)
            self.encryptData()
            self.sendResponse()

        elif msgType == "SEND":
            if not processSendMsg(self, data):
                return
            self.encryptData()
            self.sendResponse()

    def encryptData(self):
        iv, cipherText, encryptorTag = encryptDataWithAESGCM(clientConnMap[self.client].key, self.data)
        self.dataToBeSentToClient = iv + '<<>>' + cipherText + '<<>>' + encryptorTag

    def sendResponse(self):
        outputSockList.append(self.client)
        clientConnMap[self.client].messageQueue.put(self.dataToBeSentToClient)

# Fucntion to process login message
def processLoginMsg1(msgObj, data):
    chalResp, userName, msgObj.clientTS = data[1], data[2], data[3]
    userNotFound = False
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
                    try:
                        msgObj.user, msgObj.salt, msgObj.hashValue = line.split('<<>>', 2)
                    except:
                        userNotFound = True
                        break
                    userNotFound = False
                    break
                else:
                    userNotFound = True
    except:
        print "Error in accessing the Password file"
        return False
    if userNotFound:
        msgObj.data = pickle.dumps(('LOGIN1', False, False))
        return True
    if userName in activeUserlist:
        msgObj.data = pickle.dumps(('LOGIN1', False, True))
        return True
    clientConnMap[msgObj.client].userName = userName
    activeUserlist.append(userName)
    userConnMap[userName] = msgObj.client
    serverTimeStampToClient = generateCurrentTime()
    dataToSend = (msgObj.salt, msgObj.user, msgObj.clientTS, serverTimeStampToClient)
    msgObj.data = pickle.dumps(dataToSend)
    return True

# Function to process second login message
def processLoginMsg2(msgObj, data):
    password, userName, msgObj.clientTS, clientConnMap[msgObj.client].publicKey = data[1], data[2], data[3], data[4]
    if not verifyTimeStamp(msgObj.clientTS):
        print "Found Replay attack, Dropping packet from", msgObj.getpeername()
        return False
    if not verifyHashSaltPassword(password, userName):
        msgObj.data = pickle.dumps(('LOGIN2', False))
        return True
    print 'New user', userName, 'authenticated!!'
    clientConnMap[msgObj.client].authenticated = True
    #destroy old symmetri key we used for previous messages and generate new shared key
    clientConnMap[msgObj.client].key = os.urandom(32) #AES 256
    serverTimeStampToClient = generateCurrentTime()
    dataToSend = (userName, msgObj.clientTS, serverTimeStampToClient)
    msgObj.data = pickle.dumps(dataToSend)
    return True

# Fucntion to process SEND message
def processSendMsg(msgObj, data):
    msgObj.clientTS, senderUserName, peerClientUserName = data[1], data[2], data[3]
    if not verifyTimeStamp(msgObj.clientTS):
        print "Found Replay attack, Dropping packet from", msgObj.getpeername()
        return False
    if peerClientUserName not in activeUserlist:
        msgObj.data = pickle.dumps(('SEND', False))
        return True
    peerClient = userConnMap[peerClientUserName]
    peerClientTimeStamp = generateCurrentTime()
    dataToSend = (peerClientTimeStamp, senderUserName, peerClientUserName,
                  clientConnMap[msgObj.client].publicKey, clientConnMap[msgObj.client].clientIpPort)
    data = pickle.dumps(dataToSend)

    iv, cipherText, encryptorTag = encryptDataWithAESGCM(clientConnMap[peerClient].key, data)
    ticket = iv + '<<>>' + cipherText + '<<>>' + encryptorTag

    serverTimeStampToClient = generateCurrentTime()
    dataToSend = ('SEND', True, serverTimeStampToClient, peerClientTimeStamp, senderUserName,
                  peerClientUserName, clientConnMap[peerClient].publicKey,
                  clientConnMap[peerClient].clientIpPort, ticket)

    msgObj.data = pickle.dumps(dataToSend)
    return True

# Signal handler for SIGTERM and SIGINT
def signal_handler (signal, frame):
    print
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
# wThread    -> Worker Thread object
if __name__ == "__main__":
    serverAddress = parser()
    serverSock = TcpServer(serverAddress)
    rThread = receiverThread(1, "Receiver Thread")
    wThread = workerThread(2, "Worker 1")
    wThread.start()
    rThread.start()
    main()
    cleanup()
