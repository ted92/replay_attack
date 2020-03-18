#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

import socket, threading
from utils import generate_nonce, verify_nonce
import sys
import pickle
from utils import Colors, PORT, MAX_SIZE, \
    OK, NO_CONTENT, NOTFOUND, HOST, Verifier, aes_encode, aes_decode, TIME, ACCEPTED
import datetime
import time

AES_KEY = b'TheForceIsStrong'  # 16bit AES key
"""
process flow:
    ( 1 ) N --> S: {N_N}K
    ( 2 ) S --> N: N_N, {N_S}K
    ( 3 ) N --> S: N_S
"""


class ClientThread(threading.Thread):
    def __init__(self, client_address, clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.client_address = client_address
        self.aes = AES_KEY  # aes key
        self.client_id = {}  # dict with client id and n_s associated with it
        # { id1 : server_nonce1,
        #   id2 : server_nonce2,
        #       ...
        #   idn : server_noncen }
        self.nonce = None
        print("New connection added: ", self.client_address)

    def run(self):
        print("Connection from : " + Colors.WARNING, self.client_address, Colors.ENDC)
        while True:
            msg = ''
            code = ACCEPTED
            data = self.csocket.recv(MAX_SIZE)
            while data == b'':
                time.sleep(5)
                data = self.csocket.recv(MAX_SIZE)
            message = pickle.loads(data)
            if message['dest'] == 'setup':
                # step ( 1 ) incoming from the client
                # decrypt message with n, c, t
                n = message['n']
                c = message['c']
                t = message['t']
                n_n = aes_decode(n, c, t, self.aes)
                # generate server nonce for this particular node and assign an id to it
                self.nonce = generate_nonce()
                client_id = generate_nonce()
                # generate unique key
                while client_id in self.client_id:
                    client_id = generate_nonce()
                # assign a client id to a specific nonce
                self.client_id[client_id] = self.nonce
                # encrypt server nonce
                n, c, t = aes_encode(self.aes, self.nonce)
                print(Colors.BOLD + 'S --> N: N_N, {N_S}K' + Colors.ENDC)
                print('\t' + Colors.BOLD + 'N_N: ' + Colors.ENDC + str(n_n))
                print('\t' + Colors.BOLD + 'N_S: ' + Colors.ENDC + str(self.nonce))
                print('\t' + Colors.BOLD + '{N_S}K : (n, c, t)' + Colors.ENDC)
                to_send = {'id': client_id, 'n_n': n_n, 'n': n, 'c': c, 't': t}
                self.csocket.sendall(pickle.dumps(to_send))
                code = ACCEPTED
            elif message['dest'] == 'confirmation':
                # verify the node shares the same key
                server_nonce_sent = self.client_id[message['id']]
                if verify_nonce(server_nonce_sent, message['n']):
                    code = OK
                    msg = Colors.OKGREEN + 'CONGRATULATIONS, YOU ARE VERIFIED!' + Colors.ENDC
                else:
                    code = NOTFOUND
                    msg = Colors.FAIL + "ERROR: Ah-ah-ah! You didn't say the magic word!" + Colors.ENDC
            if code == OK or code == NOTFOUND:
                self.csocket.sendall(pickle.dumps(msg))
                break
        print("Client at ", self.client_address, " disconnected...")


class Server:
    """
    Server class -- The server, upon request, needs the client to prove it has a certain key K, and the
    server needs to prove that back to the client.

    While the server is up and running, the students have to try to make the server believe they have the secret key.

    MESSAGE FORMAT:
    {   'id'        : <id>,
        'sequence'  : <sequence_n>,
        'type'      : <type of connection>,
        'content'   : <message content>
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
