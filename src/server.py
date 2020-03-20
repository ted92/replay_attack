#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket, threading
from utils import generate_nonce, verify_nonce, verify_timestamp
import sys
import pickle
from utils import Colors, PORT, MAX_SIZE, \
    OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode, TIME, ACCEPTED, TIMEOUT, ERROR, MESSAGE_OK
from datetime import datetime
import time

AES_KEY = b'TheForceIsStrong'  # 16bit AES key
"""
    process flow:
    ( 1 ) A --> S:  A, {T_A, B, K_AB}K_AS   	where T_A is current time
    ( 2 ) S --> B:  {T_S, A, K_AB}K_BS   	    where T_S is current time
"""
message_to_send = {}


class ClientThread(threading.Thread):
    def __init__(self, client_address, clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.client_address = client_address
        self.aes = AES_KEY  # aes key
        self.aes_client = b''
        self.timestamp = datetime.now()
        self.sender = ''
        self.receiver = ''
        self.timeout = TIMEOUT
        print("New connection added: ", self.client_address)

    def run(self):
        print("Connection from : " + Colors.WARNING, self.client_address, Colors.ENDC)
        global message_to_send
        while True:
            # receive the message and check timestamp
            data = self.csocket.recv(MAX_SIZE)
            while data == b'':
                time.sleep(5)
                data = self.csocket.recv(MAX_SIZE)
            message = pickle.loads(data)
            if message['dest'] == 'send':
                # step ( 1 ) incoming from the client
                # decrypt message with n, c, t
                n = message['n']
                c = message['c']
                t = message['t']
                self.sender = message['sender']
                message = pickle.loads(aes_decode(n, c, t, self.aes))  # message = {T_A, B, K_AB}
                self.timestamp = message['timestamp']
                self.aes_client = message['key']
                self.receiver = message['rcv']
                if verify_timestamp(self.timestamp, self.timeout):
                    # verified, make the message
                    self.timestamp = datetime.now()
                    to_encrypt = {'timestamp': self.timestamp, 'sender': 'A', 'key': self.aes_client}  # T_S, A, K_AB
                    n, ciphertext, tag = aes_encode(self.aes, pickle.dumps(to_encrypt))  # {T_S, A, K_AB}K_BS
                    message_to_send = {'n': n, 'c': ciphertext, 't': tag, 'ts': MESSAGE_OK}
                    self.csocket.sendall(pickle.dumps({'ts': MESSAGE_OK}))
                else:
                    # message not verified Timestamp expired
                    message_to_send = {'ts': ERROR}
            elif message['dest'] == 'recv':
                self.csocket.sendall(pickle.dumps(message_to_send))


class Server:
    """
    Server class -- The server, upon request, needs to verify the timestamp, and forward the key to the
    other receiver node

    MESSAGE FORMAT INCOMING:
    {
        'dest': <destination_msg>,
        'sender': <sender>,
        'n': <nonce>,
        'c': <ciphertext>,
        't': <tag>
        }
    The encrypted message is:
    {
        'timestamp': <ts>,
        'rcv': <receiver>,
        'key': <KEY_AB>
        }

    MESSAGE FORMAT OUTGOING
    {
        'n': <nonce>,
        'c': <ciphertext>,
        't': <tag>
        }
    The encrypted message is:
    {
    'sender': <sender>,
    'timestamp': <ts>,
    'key': <shared_key>
    }
    """
    def __init__(self):
        self.serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socket object
        self.aes = AES_KEY  # aes key
        self.clientsocket = []

    def run(self):
        """
        it runs the server
        :return:
        """
        # bind to the port
        self.serversocket.bind(('0.0.0.0', PORT))
        print("Listening on: " + Colors.BOLD + HOST + ":" + str(PORT) + Colors.ENDC)
        print("... waiting for a connection", file=sys.stderr)
        try:
            while True:
                # queue up to 5 requests
                self.serversocket.listen(5)
                clientsocket, addr = self.serversocket.accept()
                print("Got a connection from " + Colors.WARNING + "%s" % str(addr) + Colors.ENDC)
                self.clientsocket.append(clientsocket)
                newthread = ClientThread(addr, self.clientsocket[-1])
                newthread.start()
        finally:
            for cskt in self.clientsocket:
                cskt.close()


if __name__ == "__main__":
    try:
        srv = Server()
        srv.run()
    except KeyboardInterrupt:
        for cs in srv.clientsocket:
            cs.close()
        print(Colors.WARNING + "Shutting down ... " + Colors.ENDC)
