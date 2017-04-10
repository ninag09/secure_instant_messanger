#!/usr/bin/python
import socket
import select
import sys
import errno
import threading
import argparse
import time
import signal
import Queue

# Global varibles
# clientSockList -> Active client connections
# outputSockList -> Pending connections awaiting reply
# messageQueues  -> Queues for active client connections
clientSockList = []
outputSockList = []
messageQueues = {}

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
            messageQueues[s].put(data)
            if s not in outputSockList:
                outputSockList.append(s)
        else:
            if s in outputSockList:
                outputSockList.remove(s)
            clientSockList.remove(s)
            print "Client removed,", len(clientSockList), "active clients"
            s.close()
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
        except:
            self.serverClose()
            raise

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
        messageQueues[conn] = Queue.Queue()
        print "New client added,", len(clientSockList), "active clients"

    def serverClose(self):
        self.socket.close()

# Message Handler class. Responsible for processing the client message
class MessageHandler:
    def __init__(self):return

# Signal handler for SIGTERM and SIGINT
def signal_handler (signal, frame):
    print "Signal Received for Shutdown, Cleaning Up..."
    cleanup()
    sys.exit(0)

# CleanUp before exiting. Wait for threads to finish jobs and close socket
def cleanup():
    rThread.shutdown()
    rThread.join()
    serverSock.serverClose()
    print "Shutting down server..."

# Read arguments
def parser():
    # Parser to read the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', '--server_port', type=int,  required='True', help="Server Port to Bind")

    # Parse the arguments and check for validity
    args = parser.parse_args()
    if args.server_port < 0 or args.server_port > 65535:
        print "Invalid Port..."
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
    rThread = receiverThread(1, "Thread-1", clientSockList)
    rThread.start()
    main()
    cleanup()
