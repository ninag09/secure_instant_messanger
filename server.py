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

clientSockList = []
outputSockList = []
messageQueues = {}
shutdown = 0

# Signal handler to cath Interrupts
def signal_handler (signal, frame):
	print "Interrupt Received Cleaning Up..."
	cleanup()
	print "Exiting Main Thread"
	sys.exit(0)

def cleanup():
	rThread.shutdown()
	rThread.join()
	serverSock.serverClose()
	print "Shutting down server..."

class receiverThread(threading.Thread):

	def __init__(self, threadId, name, clientSockList):
		threading.Thread.__init__(self)
		self.threadId = threadId
		self.name = name
		self.clientSockList = clientSockList
		self._is_shutdown = threading.Event()
		self._shutdown_request = False

	def run(self):
		print "Starting Receiver " + self.name
		try:
			while not self._shutdown_request:
				print self.clientSockList
				receiveMessage()
		finally:
			self._shutdown_request = False
			self._is_shutdown.set()

		print "Exited Receiver " + self.name

	def shutdown(self):
		self._shutdown_request = True
		self._is_shutdown.wait()

def receiveMessage():
	pollTimeout = 2#Just for testing purpose
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
		if s in outputSockList:
			outputSockList.remove(s)
		s.close()
		del messageQueues[s]

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
        conn, addr = self.socket.accept()
        conn.setblocking(0)
        clientSockList.append(conn)
        messageQueues[conn] = Queue.Queue()

    def serverClose(self):
        self.socket.close()

class MessageHandler:
    def __init__(self):return

def main():
	signal.signal(signal.SIGINT, signal_handler)
	signal.signal(signal.SIGTERM, signal_handler)
	while(True):
		serverSock.serverAccept()

def parser():
	# Parser to read the arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-sp', '--server_port', type=int,  required='True', help="Server Port to Bind")

	# Parse the arguments and check for validity
	args = parser.parse_args()
	if args.server_port and args.server_port > 65535:sys.exit(1)

	serverAddress = ('',args.server_port)
	return serverAddress

if __name__ == "__main__":
	serverAddress = parser()
	serverSock = TcpServer(serverAddress, MessageHandler)
	rThread = receiverThread(1, "Thread-1", clientSockList)
	rThread.start()
	main()
	cleanup()
