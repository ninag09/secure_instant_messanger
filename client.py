#!/usr/bin/python
import os
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

sockList = []
peerSockMap = {}
peerKeyMap = {}
peerKeyAccMap = {}
firstMsg = ''

# Read Arguments
def parser():
    # Parser to read the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-sip', '--server_ip', required='True', help="Enter Server IP")
    parser.add_argument('-sp', '--server_port', type=int, required='True', help="Server Port to Bind")

    # Parse the arguments, check for validity and form sign-in message
    args = parser.parse_args()
    try:
        socket.inet_pton(socket.AF_INET,args.server_ip)
    except socket.error:
        print "Invalid IP Address"
        sys.exit(1)
    if args.server_port < 0 and args.server_port > 65535:
        print "Invalid Port... Port Range [0-65535]"
        sys.exit(1)
    return (args.server_ip, args.server_port)

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
    pollTimeout = 0.2 #Just for testing purpose
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
            sockList.remove(s)
            s.close()

    for s in eList:
        sockList.remove(s)
        s.close()

def processPeerMessage(sock, data):
    decryptedData = decryptDataWithAES(data, peerKeyAccMap[sock][0])
    msg = pickle.loads(decryptedData)
    addr = sock.getpeername()
    flush('<- < From '+str(addr[0])+':'+str(addr[1])+': '+peerKeyAccMap[sock][1]+' >: ')
    for i in range (0,len(msg)): print msg[i],
    flush('+> ')

def handleTicketMsg(sock):
    recvMsg = sock.recv(4096)
    decryptedData = decryptDataWithAES(recvMsg, server.symmKey)
    data = pickle.loads(decryptedData)
    peerTimestamp, peerUsername = data[0], data[1]
    username, peerPublicKey, peerIpPort = data[2], data[3], data[4]
    #!TODO verifyTimeStamp
    timestampToPeer = generateCurrentTime()
    data = pickle.dumps((peerTimestamp, timestampToPeer, peerUsername, username))
    authString = b"ChatApp"
    P2PSymmKey = os.urandom(32)
    peerKeyAccMap[sock] = P2PSymmKey, peerUsername
    try:
        buf = StringIO.StringIO(peerPublicKey)
        peerPublicKey = serialization.load_pem_public_key(buf.read(), backend = default_backend())
        cipherKey = peerPublicKey.encrypt(P2PSymmKey,padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),label=None))
        iv = os.urandom(32)
        encryptor = Cipher(algorithms.AES(P2PSymmKey),modes.GCM(iv),backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(authString)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
    except:
        print "Error in Encryption, closing peer connection.."
        sock.close()
    dataToBeSentToPeer = iv + '<<>>' + ciphertext + '<<>>' + tag + '<<>>' + authString + '<<>>' + cipherKey
    sock.send(dataToBeSentToPeer)

def handleTicketMsg1(sock):
    recvMsg = sock.socket.recv(4096)
    cipherKey = recvMsg.split('<<>>')[4]
    P2PSymmKey =  RSADecryption(cipherKey)
    sock.P2PSymmKey = P2PSymmKey
    decryptedData = decryptDataWithAES(recvMsg, sock.P2PSymmKey)
    data = pickle.loads(decryptedData)
    peerClientTimeStampToPeer, peerClientTimeStampFromPeer = data[0], data[1]
    username, peerUsername = data[2], data[3]
    #!TODO verifyTimeStamp
    peerClientTimeStampToPeer = generateCurrentTime()
    data = pickle.dumps((peerClientTimeStampToPeer, firstMsg))
    authString = b"ChatApp"
    iv, cipherText, encryptorTag = encryptDataWithAESGCM(P2PSymmKey, data,authString)
    dataToBeSentToPeerClient = iv + '<<>>' + cipherText + '<<>>' + encryptorTag + '<<>>' + authString
    sock.socket.send(dataToBeSentToPeerClient)

def handleTicketMsg2(sock):
    recvMsg = sock.recv(4096)
    decryptedData = decryptDataWithAES(recvMsg, peerKeyAccMap[sock][0])
    data = pickle.loads(decryptedData)
    timestamp, msg = data[0], data[1]
    #!TODO verifyTimeStamp
    addr = sock.getpeername()
    flush('<- <From '+str(addr[0])+':'+str(addr[1])+':'+peerKeyAccMap[sock][1]+'>: ')
    for i in range (0,len(msg)): print msg[i],
    flush('+> ')

def processServerMessage(sock, data):
    decryptedData = decryptDataWithAES(data, server.symmKey)
    msg = pickle.loads(decryptedData)
    msgType = msg[0]
    if msgType == 'LIST':
        handleListMsg(msg)
    elif msgType == 'SEND':
        handleSendMsg(msg)

def handleSendMsg(data):
    if not data[1]:
        flush('<- User not found')
        flush('+> ')
        return
    serverTimeStampToClient, peerClientTimeStamp, senderUserName = data[2], data[3], data[4]
    #!TODO why peerClientPublicKey???
    peerUserName, peerClientPublicKey = data[5], data[6]
    peerIpPort, ticket = data[7], data[8]
    #!TODO verifyTimeStamp
    pConn = peerConn(peerIpPort, senderUserName, ticket)
    peerSockMap[pConn.username] = pConn.socket
    peerKeyMap[pConn.socket] = pConn.P2PSymmKey

def handleListMsg(data):
    timestamp, activeUserlist = data[1], data[2]
    #!TODO verifyTimeStamp
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

class peerConn:

    def __init__(self, peerAddress, username, ticket):
        self.peerAddress = peerAddress
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.peerConnect()
        except:
            print "Couldn't connect to ", self.username
            self.peerClose()
        self.socket.send(ticket)
        handleTicketMsg1(self)
        self.socket.setblocking(0)
        sockList.append(self.socket)

    def peerConnect(self):
        self.socket.connect(self.peerAddress)

    def peerClose(self):
        self.socket.close()

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
        handleTicketMsg(conn)
        handleTicketMsg2(conn)
        conn.setblocking(0)
        sockList.append(conn)

    def clientClose(self):
        self.socket.close()

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

def generateCurrentTime():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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

def login():
    username = raw_input("Username:")
    password = getpass.getpass("Password:")
    createLoginMsg1(username)
    createLoginMsg2(username, password)
    createLoginMsg3()
    print getLoginResponse()
    sockList.append(server.socket)
    server.socket.setblocking(0)
    server.username = username

def createLoginMsg1(username):
    timestamp = generateCurrentTime()
    data = pickle.dumps(('LOGIN1', server.challengeResponse, username, timestamp))
    authString = b"ChatApp"
    server.symmKey = os.urandom(32)
    iv, ciphertext, encryptorTag = encryptDataWithAESGCM(server.symmKey, data, authString)
    cipherKey = RSAEncryption(server.symmKey)
    dataToBeSentToServer = iv + '<<>>' + ciphertext + '<<>>' + encryptorTag + '<<>>' + authString + '<<>>' + cipherKey
    server.socket.send(dataToBeSentToServer)

def createLoginMsg2(username, password):
    data = getLoginResponse()
    decryptedData = decryptDataWithAES(data, server.symmKey)
    msg = pickle.loads(decryptedData)
    salt, timestamp, serverTimestamp = msg[0], msg[2], msg[3]
    #! TODO add verifyTimeStamp
    passwdHash = saltedPasswordHash(password, salt)
    timestamp = generateCurrentTime()
    loginMsg2 = pickle.dumps(('LOGIN2', passwdHash, username, timestamp, asymKeys.publicKey))
    encryptSend(loginMsg2)

def createLoginMsg3():
    data = getLoginResponse()
    cipherKey = data.split('<<>>')[4]
    server.symmKey = RSADecryption(cipherKey)
    decryptedData = decryptDataWithAES(data, server.symmKey)
    msg = pickle.loads(decryptedData)
    timestamp, serverTimestamp = msg[1], msg[2]
    #! TODO add verifyTimeStamp
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

def encryptSend(data):
    authString = b"ChatApp"
    iv, cipherText, encryptorTag = encryptDataWithAESGCM(server.symmKey, data, authString)
    dataToBeSentToServer = iv + '<<>>' + cipherText + '<<>>' + encryptorTag + '<<>>' + authString
    server.socket.send(dataToBeSentToServer)

def saltedPasswordHash(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = 32,
                     salt = salt, iterations = 100000,
                     backend = default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password))

def decryptDataWithAES(data,symmKey):
    try:
        parts = data.split('<<>>')
        iv,cipherText,encryptorTag, authString = parts[0], parts[1], parts[2], parts[3]
        decryptor = Cipher(algorithms.AES(symmKey),modes.GCM(iv, encryptorTag),backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(authString)
        return decryptor.update(cipherText) + decryptor.finalize()
    except Exception as e:
        raise
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

def RSAEncryption(data):
    try:
        cipherKey = asymKeys.serverPublicKey.encrypt(data,
                     padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                     algorithm=hashes.SHA1(), label=None))
        return cipherKey
    except:
        print "Error in RSA encryption! Aborting the client application!"
        cleanup()

def encryptDataWithAESGCM(key, data, authString):
    try:
        iv = os.urandom(32)
        encryptor = Cipher(algorithms.AES(key),modes.GCM(iv),backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(authString)
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return (iv, ciphertext, encryptor.tag)
    except:
        print "Error in Encrypting the data! Aborting the client application!!"
        cleanup()

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
    #!TODO Possible race condition during login
    rThread.shutdown()
    rThread.join()
    server.serverClose()
    clientsock.clientClose()
    print "Terminating Client..."
    sys.exit(0)

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

def handleSendCmd(peerUser, msg):
    if server.socket not in sockList:
        flush("Server not Available"+'\n',False)
        return
    timestamp = generateCurrentTime()
    if peerUser in peerSockMap.keys():
        data = pickle.dumps(msg)
        authString = b"ChatApp"
        iv, cipherText, encryptorTag = encryptDataWithAESGCM(peerKeyMap[peerSockMap[peerUser]], data, authString)
        dataToPeer = iv + '<<>>' + cipherText + '<<>>' + encryptorTag + '<<>>' + authString
        peerSockMap[peerUser].send(dataToPeer)
        return
    data = pickle.dumps(('SEND', timestamp, server.username, peerUser))
    encryptSend(data)
    global firstMsg
    firstMsg = msg

def handleListCmd():
    if server.socket not in sockList:
        flush("Server not Available"+'\n',False)
        return
    timestamp = generateCurrentTime()
    data = pickle.dumps(('LIST', timestamp, server.username))
    encryptSend(data)

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
