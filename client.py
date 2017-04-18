#!/usr/bin/python
import os
import re
import sys
import time
import socket
import select
import pickle
import signal
import base64
import getpass
import argparse
import threading
import pickle
import StringIO

from base64 import b64encode
from datetime import datetime, date
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#sockList -> list of active sockets
#peerSockMap -> peer connection sock objects
#peerKeyMap -> peer symmetricKey
sockList = []
peerSockMap = {}
peerKeyMap = {}

# Read config file for Server IP and Port
def parser():
    try:
        configFile = open("Config.conf", "rb")
        with configFile as configFromFile:
            lines = configFromFile.readlines()
            for line in lines:
                line = line.rstrip('\n')
                if re.match('SERVER_IP', line):
                    serverIP = line.split('=', 1)
                elif re.match('SERVER_PORT', line):
                    serverPort = line.split('=', 1)
    except:
        print "Error in accessing the Config file"
        return False

    server_ip = serverIP[1]
    server_port = int(serverPort[1])
    try:
        socket.inet_aton(server_ip)
    except socket.error:
        print "Invalid IP Address"
        sys.exit(1)
    if server_port < 0 and server_port > 65535:
        print "Invalid Port... Port Range [0-65535]"
        sys.exit(1)
    return (server_ip, server_port)

# Signal handler for SIGTERM and SIGINT
def signal_handler (signal, frame):
    print "Signal Received for Shutdown, Cleaning Up..."
    cleanup()

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
    rList, wList, eList = select.select(sockList, [], sockList, pollTimeout)

    for s in rList:
        if s == clientsock.socket:
            clientsock.clientAccept()
            continue
        try:
            data = s.recv(4096)
        except:
            continue
        if data:
            if s == server.socket:
                processServerMessage(s,data)
            else:
                processPeerMessage(s,data)
        else:
            if s == server.socket:
                flush("Connection terminated with server..."+'\n'+"+> ")
            if s in peerKeyMap.keys():
                flush(peerKeyMap[s][1]+" logged out"+'\n'+"+> ")
                del peerSockMap[peerKeyMap[s][1]]
                del peerKeyMap[s]
            sockList.remove(s)
            s.close()

    for s in eList:
        sockList.remove(s)
        s.close()

#Process Peer Messages
def processPeerMessage(sock, data):
    try:
        decryptedData = decryptDataWithAES(data, peerKeyMap[sock][0])
        msg = pickle.loads(decryptedData)
    except:
        print "Invalid Message"
        return
    timestamp, msg, hashMessage, username = msg[0], msg[1], msg[2], msg[3]
    if not verifyTimeStamp(timestamp):
        print 'Found Replay attack, Dropping the packet!!'
        return
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    hashOriginalMsg = digest.finalize()
    if (hashOriginalMsg != hashMessage):
        print "Message has been modified, Dropping the packet!!"
        return
    addr = sock.getpeername()
    flush('<- < From '+str(addr[0])+':'+str(addr[1])+': '+peerKeyMap[sock][1]+' >: ')
    print msg
    flush('+> ',False)

# Handle ticket (originated from server) sent by client trying to establish connection
def handleTicketMsg(sock):
    try:
        recvMsg = sock.recv(4096)
        decryptedData = decryptDataWithAES(recvMsg, server.symmKey)
        data = pickle.loads(decryptedData)
    except:
        print "Invalid Message"
        sock.close()
        return False
    peerTimestamp, peerUsername = data[0], data[1]
    username, peerPublicKey, peerIpPort = data[2], data[3], data[4]
    if not verifyTimeStamp(peerTimestamp):
        print 'Found Replay attack, Dropping packet and Closing connection!!'
        sock.close()
        return False
    timestampToPeer = generateCurrentTime()
    data = pickle.dumps((peerTimestamp, timestampToPeer, peerUsername, username))
    P2PSymmKey = os.urandom(32)
    peerKeyMap[sock] = P2PSymmKey, peerUsername
    peerSockMap[peerUsername] = sock
    try:
        buf = StringIO.StringIO(peerPublicKey)
        peerPublicKey = serialization.load_pem_public_key(buf.read(), backend = default_backend())
        cipherKey = peerPublicKey.encrypt(P2PSymmKey,padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),label=None))
        iv = os.urandom(32)
        encryptor = Cipher(algorithms.AES(P2PSymmKey),modes.GCM(iv),backend=default_backend()).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
    except:
        print "Error in Encryption, closing peer connection.."
        sock.close()
        return False
    dataToBeSentToPeer = iv + '<<>>' + ciphertext + '<<>>' + tag + '<<>>' + cipherKey#+ authString + '<<>>' + cipherKey
    sock.send(dataToBeSentToPeer)
    return True

# Authenticate peer
def handleTicketMsg1(sock):
    recvMsg = sock.socket.recv(4096)
    cipherKey = recvMsg.split('<<>>')[3]
    P2PSymmKey =  RSADecryption(cipherKey)
    sock.P2PSymmKey = P2PSymmKey
    decryptedData = decryptDataWithAES(recvMsg, sock.P2PSymmKey)
    data = pickle.loads(decryptedData)
    peerClientTimeStampToPeer, peerClientTimeStampFromPeer = data[0], data[1]
    username, peerUsername = data[2], data[3]
    if (peerClientTimeStamp != peerClientTimeStampToPeer) or not verifyTimeStamp(peerClientTimeStampFromPeer):
        print 'Found Replay attack, Dropping packet!!'
        return False
    peerClientTimeStampToPeer = generateCurrentTime()
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(firstMsg)
    hashMessage = digest.finalize()
    data = pickle.dumps((peerClientTimeStampToPeer, firstMsg, hashMessage, username))
    iv, cipherText, encryptorTag = encryptDataWithAESGCM(P2PSymmKey, data)

    dataToBeSentToPeerClient = iv + '<<>>' + cipherText + '<<>>' + encryptorTag
    sock.socket.send(dataToBeSentToPeerClient)
    return True

# Print the message recevied from authenticated peer
def handleTicketMsg2(sock):
    recvMsg = sock.recv(4096)
    decryptedData = decryptDataWithAES(recvMsg, peerKeyMap[sock][0])
    data = pickle.loads(decryptedData)
    timestamp, msg, hashMessage, username = data[0], data[1], data[2], data[3]
    if not verifyTimeStamp(timestamp):
        print 'Found Replay attack, Dropping packet!!'
        return False
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    hashOriginalMsg = digest.finalize()
    if (hashOriginalMsg != hashMessage):
        print "Message has been modified, Dropping Packet!!"
        return False
    addr = sock.getpeername()
    flush('<- < From '+str(addr[0])+':'+str(addr[1])+' : '+peerKeyMap[sock][1]+' >: ')
    print msg
    flush('+> ',False)
    return True

# Process the messages from server (List and Send)
def processServerMessage(sock, data):
    decryptedData = decryptDataWithAES(data, server.symmKey)
    msg = pickle.loads(decryptedData)
    msgType = msg[0]
    if msgType == 'LIST':
        handleListMsg(msg)
    elif msgType == 'SEND':
        handleSendMsg(msg)

# Handle send message reply from server
def handleSendMsg(data):
    if not data[1]:
        flush('<- User not found')
        flush('+> ')
        return
    global peerClientTimeStamp
    serverTimeStampToClient, peerClientTimeStamp, senderUserName = data[2], data[3], data[4]
    peerUserName, peerClientPublicKey = data[5], data[6]
    peerIpPort, ticket = data[7], data[8]
    if not verifyTimeStamp(serverTimeStampToClient):
        print 'Found Replay attack, Dropping packet!!'
        return
    pConn = peerConn(peerIpPort, peerUserName, ticket)
    if not pConn.peerAuthFailed:
        peerSockMap[pConn.username] = pConn.socket
        peerKeyMap[pConn.socket] = pConn.P2PSymmKey, pConn.username

# Handle list message reply from server
def handleListMsg(data):
    timestamp, activeUserlist = data[1], data[2]
    if not verifyTimeStamp(timestamp):
        print 'Found Replay attack, Dropping packet!!'
        return
    flush('<- Signed-In Users: ')
    for numOfUsers in range (0,len(activeUserlist)):
        if numOfUsers != len(activeUserlist)-1:
            print activeUserlist[numOfUsers]+',',
    print activeUserlist[numOfUsers]
    flush('+> ', False)

def flush(data=None, nextLine=True):
    if nextLine: sys.stdout.write('\n')
    if data: sys.stdout.write(data)
    sys.stdout.flush()

# Class peerConn
# This class initiates the new connection after it receives the ticket
# from the server, after authentication the message is sent
class peerConn:
    def __init__(self, peerAddress, username, ticket):
        self.peerAddress = peerAddress
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peerAuthFailed = False
        try:
            self.peerConnect()
        except:
            print "Couldn't connect to ", self.username
            self.peerClose()
        self.socket.send(ticket)
        if handleTicketMsg1(self):
            self.socket.setblocking(0)
            sockList.append(self.socket)
        else:
            self.peerAuthFailed = True

    def peerConnect(self):
        self.socket.connect(self.peerAddress)

    def peerClose(self):
        self.socket.close()

# class clientsConn
# This class is responsible for handling connection requests from other
# peers it'll add the socket into sockList after authentication
class clientsConn:

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.clientBind()
            self.clientActivate()
        except:
            rThread.shutdown()
            rThread.join()
            self.clientClose()
            sys.exit(0)
        sockList.append(self.socket)

    def clientBind(self):
        ipAddr = server.socket.getsockname()[0]
        self.socket.bind((ipAddr,0))
        self.sockAddress = self.socket.getsockname()

    def clientActivate(self):
        self.socket.listen(5)

    def clientAccept(self):
        try:
            conn, addr = self.socket.accept()
        except socket.error:
            return
        if handleTicketMsg(conn):
            if handleTicketMsg2(conn):
                conn.setblocking(0)
                sockList.append(conn)

    def clientClose(self):
        self.socket.close()

# class serverConn
# This class is responsible for establishing connection with server and handles
# Login, List and initial Send command
class serverConn:

    def __init__(self, serverAddress):
        self.serverAddress = serverAddress
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.serverConnect()
            solveChallenge(self)
        except Exception as e:
            print "Check Server Availability"
            rThread.shutdown()
            rThread.join()
            self.serverClose()
            sys.exit(0)

    def serverConnect(self):
        self.socket.connect(self.serverAddress)

    def serverClose(self):
        self.socket.close()

# Generate Current time for timestamp to mitigate replay attacks
def generateCurrentTime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Verify the receiced timestamp
def verifyTimeStamp(serverTimeStamp):
    fmt = '%Y-%m-%d %H:%M:%S'
    clientTimeStamp = datetime.now().strftime(fmt)
    clientTimeStamp = datetime.strptime(clientTimeStamp, fmt)
    serverTimeStamp = datetime.strptime(serverTimeStamp, fmt)
    daysDiff = (clientTimeStamp-serverTimeStamp).days
    # convert days into minutes
    minutesDiff = daysDiff * 24 * 60
    if (minutesDiff > 1):
        return False
    return True

# Login function handles the initial login messages to server for mutual
# authentication and terminates the client in case of any errors
def login():
    username = raw_input("Username:")
    password = getpass.getpass("Password:")
    createLoginMsg1(username)
    createLoginMsg2(username, password)
    createLoginMsg3()
    data = getLoginResponse()
    print decryptDataWithAES(data, server.symmKey)
    sockList.append(server.socket)
    server.socket.setblocking(0)
    server.username = username

# Initial login message responding with server's challenge
def createLoginMsg1(username):
    timestamp = generateCurrentTime()
    data = pickle.dumps(('LOGIN1', server.challengeResponse, username, timestamp))
    server.symmKey = os.urandom(32)
    iv, ciphertext, encryptorTag = encryptDataWithAESGCM(server.symmKey, data)
    cipherKey = RSAEncryption(server.symmKey)
    dataToBeSentToServer = iv + '<<>>' + ciphertext + '<<>>' + encryptorTag + '<<>>' + cipherKey
    server.socket.send(dataToBeSentToServer)

# Function to create second message from client which contains username and password
def createLoginMsg2(username, password):
    data = getLoginResponse()
    try:
        decryptedData = decryptDataWithAES(data, server.symmKey)
        msg = pickle.loads(decryptedData)
    except:
        print "Invalid Message"
        cleanup()
    if not msg[1]:
        if msg[2]:
            print "You are already logged in!!!"
            cleanup()
        print 'username or password pair not found!!' + '\n'
        cleanup()
    salt, timestamp, serverTimestamp = msg[0], msg[2], msg[3]
    if not verifyTimeStamp(serverTimestamp):
        print 'Found Replay attack, Dropping packet!!'
        cleanup()
    passwdHash = saltedPasswordHash(password, salt)
    timestamp = generateCurrentTime()
    loginMsg2 = pickle.dumps(('LOGIN2', passwdHash, username, timestamp, asymKeys.publicKey))
    encryptSend(loginMsg2)

# Function which accepts the new symmetricKey generated from server and acknowledge
def createLoginMsg3():
    data = getLoginResponse()
    try:
        cipherKey = data.split('<<>>')[3]
        server.symmKey = RSADecryption(cipherKey)
        decryptedData = decryptDataWithAES(data, server.symmKey)
        msg = pickle.loads(decryptedData)
    except:
        print "Invalid Message"
        cleanup()
    if not msg[1]:
        print "username or password pair not found!!"
        cleanup()
    timestamp, serverTimestamp = msg[1], msg[2]
    if not verifyTimeStamp(serverTimestamp):
        print 'Found Replay attack, Dropping packet!!'
        cleanup()
    loginMsg3 = pickle.dumps(('LOGIN3', serverTimestamp, clientsock.socket.getsockname()))
    encryptSend(loginMsg3)

def getLoginResponse():
    server.socket.settimeout(5)
    try:
        loginResponse = server.socket.recv(4096)
    except:
        print "Server not responding"
        cleanup()
    server.socket.settimeout(None)
    return loginResponse

# Encrypt and send the data to server
def encryptSend(data):
    iv, cipherText, encryptorTag = encryptDataWithAESGCM(server.symmKey, data)
    dataToBeSentToServer = iv + '<<>>' + cipherText + '<<>>' + encryptorTag
    server.socket.send(dataToBeSentToServer)

def saltedPasswordHash(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = 32,
                     salt = salt, iterations = 100000,
                     backend = default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))

# Decrypt the data using AES
def decryptDataWithAES(data,symmKey):
    try:
        parts = data.split('<<>>')
        iv,cipherText,encryptorTag = parts[0], parts[1], parts[2]#, parts[3]
        decryptor = Cipher(algorithms.AES(symmKey),modes.GCM(iv, encryptorTag),backend=default_backend()).decryptor()
        #decryptor.authenticate_additional_data(authString)
        return decryptor.update(cipherText) + decryptor.finalize()
    except Exception as e:
        print "Error in Decrypting the data!!"
        cleanup()

# RSA Decrytion to decrypt the keys
def RSADecryption(cipherKey):
    buf = StringIO.StringIO(asymKeys.privateKey)
    clientPrivateKey = serialization.load_pem_private_key(
                        buf.read(), password=None,
                        backend = default_backend())
    symmetricKey = clientPrivateKey.decrypt(cipherKey,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                     algorithm=hashes.SHA1(), label=None))
    return symmetricKey

# RSA Encryption
def RSAEncryption(data):
    try:
        cipherKey = asymKeys.serverPublicKey.encrypt(data,
                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                     algorithm=hashes.SHA1(), label=None))
        return cipherKey
    except:
        print "Error in RSA encryption! Aborting the client application!"
        cleanup()

# AES Encryption
def encryptDataWithAESGCM(key, data):#, authString):
    try:
        iv = os.urandom(32)
        encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
        #encryptor.authenticate_additional_data(authString)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return (iv, ciphertext, encryptor.tag)
    except:
        print "Error in Encrypting the data! Aborting the client application!!"
        cleanup()

# Function to solve the server's challenge
def solveChallenge(serverSock):
    challenge = serverSock.socket.recv(1024)
    addr = serverSock.socket.getsockname()[0]
    initialBits, hashChallenge = challenge.split('<<>>', 1)
    serverSock.challengeResponse = str(bin(0))
    for i in range(0, 1024):
        index  = str(bin(i)[2:12]).rjust(10,'0')
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(initialBits+index+addr)
        hashValue = digest.finalize()
        if(hashValue == hashChallenge):
            serverSock.challengeResponse = index
            break

# class keys
# This is responsible for generating keys and retriving server public key
class keys:
    def __init__(self):
        key = generateClientRSAKeys()
        self.publicKey, self.privateKey = key[0], key[1]
        self.serverPublicKey = retrieveServerPublicKey()

def generateClientRSAKeys():
    try:
        key = rsa.generate_private_key(public_exponent=65537,
                            key_size=2048,backend=default_backend())

        clientPrivateKey = key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())

        PublicKey  = key.public_key()
        clientPublicKey = PublicKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return (clientPublicKey, clientPrivateKey)
    except:
        print "Key generation failed, Aborting client application!"
        sys.exit(1)

def retrieveServerPublicKey():
    try:
        # Read Destination Publick Key and serialize into bytes
        destinationPublicKeyFile = open("server_public_key.der", "rb")
        with destinationPublicKeyFile as publicKey:
            serverPublicKey = serialization.load_der_public_key(
                    publicKey.read(),backend = default_backend())
        return serverPublicKey
    except:
        print "Cannot read server public key, Aborting client application!"
        sys.exit(1)

# CleanUp before exiting. Wait for threads to finish jobs and close socket
def cleanup():
    rThread.shutdown()
    rThread.join()
    server.serverClose()
    clientsock.clientClose()
    print "Terminating Client..."
    sys.exit(0)

# Main function awaits for user input
def main():
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    while(True):
        cmd = raw_input('+> ')
        command = cmd.split()
        if not (len(command) and isCommand(command)):continue
        cmd = command[0]
        if cmd == 'list':
            handleListCmd()
        elif cmd == 'send':
            handleSendCmd(command[1],command[2:])
        elif cmd == 'logout':
            cleanup()

# Handle user send command
def handleSendCmd(peerUser, msg):
    timestamp = generateCurrentTime()
    if peerUser == server.username:
        flush("Messaging self???"+'\n',False)
        return
    if peerUser in peerSockMap.keys():
        message = ' '.join(msg)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(message)
        hashMessage = digest.finalize()
        data = pickle.dumps((timestamp, message, hashMessage, server.username))
        iv, cipherText, encryptorTag = encryptDataWithAESGCM(peerKeyMap[peerSockMap[peerUser]][0], data)
        dataToPeer = iv + '<<>>' + cipherText + '<<>>' + encryptorTag
        peerSockMap[peerUser].send(dataToPeer)
        return
    if server.socket not in sockList:
        flush("Server not Available"+'\n',False)
        return
    data = pickle.dumps(('SEND', timestamp, server.username, peerUser))
    encryptSend(data)
    global firstMsg
    firstMsg = ' '.join(msg)

# handle user list command
def handleListCmd():
    if server.socket not in sockList:
        flush("Server not Available"+'\n',False)
        return
    timestamp = generateCurrentTime()
    data = pickle.dumps(('LIST', timestamp, server.username))
    encryptSend(data)

# Function to check the validity of the command
def isCommand (cmd):
    if (len(cmd) == 1 and cmd[0] == 'list') or\
        (len(cmd) == 1 and cmd[0] == 'logout') or\
        (len(cmd) > 1 and cmd[0] == 'send'):
        return True
    if len(cmd) == 1 and cmd[0] == 'send':
        print "+> Invalid Command, Specify Username! 'send username message' "
    else:
        print "+> Invalid Command, Enter 'list' to see signed in users "
    return False

# Program Start
if __name__ == "__main__":
    serverAddress = parser()
    asymKeys = keys()
    rThread = receiverThread(1, "Receiver Thread")
    rThread.start()
    server = serverConn(serverAddress)
    clientsock = clientsConn()
    login()
    main()
