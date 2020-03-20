#!/usr/bin/python3
"""
Usage:
    [-k] <binary_key>   : set the binary key to send
    [-s]                : send mode
    [-r]                : receive mode
"""

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT, HOST, aes_decode, verify_timestamp
import socket
import sys
import getopt
import pickle
import time
from datetime import datetime
from utils import OK, Verifier, aes_encode, TIME, generate_nonce, verify_nonce, TIMEOUT, ERROR, MESSAGE_OK

SHARED_KEY_SERVER = b'TheForceIsStrong'  # 16bit AES key
SHARED_KEY = b'!ThePathIsClear!'


class Node:
    """
    Node class.
    It has to send a message to another node, through the server.
    process flow:
    ( 1 ) A --> S:  A, {T_A, B, K_AB}K_AS   	where T_A is current time
    ( 2 ) S --> B:  {T_S, A, K_AB}K_BS   	    where T_S is current time

    """
    def __init__(self):
        self.nodesocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server = (HOST, PORT)
        self.aes = SHARED_KEY
        self.aes_server = SHARED_KEY_SERVER
        self.nodesocket.connect(self.server)
        self.timestamp = datetime.now()
        self.timeout = TIMEOUT
        self.id = None
        self.id_comm = None  # id of the other node communicating with this instance

    def close_connection(self):
        """
        close the open connection
        :return:
        """
        self.nodesocket.close()

    def send(self):
        """
        send the message in step ( 1 ) -- node is A
        generate message A, {T_A, B, K_AB}K_AS
        """
        # todo: test this method
        self.id = 'A'  # identity
        self.timestamp = datetime.now()  # set the timestamp
        to_encrypt = {'timestamp': self.timestamp, 'rcv': 'B', 'key': self.aes}  # T_A, B, K_AB
        n, ciphertext, tag = aes_encode(self.aes_server, pickle.dumps(to_encrypt))  # {T_A, B, K_AB}K_AS
        # destination is 'send', telling the server this is the sender
        to_send = {'dest': 'send', 'sender': self.id, 'n': n, 'c': ciphertext, 't': tag}  # A, {T_A, B, K_AB}K_AS
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data

    def receive(self):
        """
        receive message in step ( 2 ) -- node is B
        message: {T_S, A, K_AB}K_BS
        :return:
        """
        to_send = {'dest': 'recv'}
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        if data['ts'] == ERROR:
            return ERROR
        n = data['n']
        c = data['c']
        t = data['t']
        message = pickle.loads(aes_decode(n, c, t, self.aes_server))  # decode the message
        self.id_comm = message['sender']
        self.timestamp = message['timestamp']
        if verify_timestamp(self.timestamp, self.timeout):
            # accept key
            self.aes = message['key']
            return MESSAGE_OK
        else:
            # reject key --> timestamp not valid
            return ERROR


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "srk:", ["key="])  # send, receive, key
        for opt, arg in opts:
            if opt == '-s' or opt == '-k':
                # sender options
                input("Press Enter to send...")
                c = Node()
                if opt == '-k':
                    # set up new key
                    c.aes = arg.encode('utf-8')
                received = c.send()
                print(received['ts'])
            elif opt == '-r':
                # receive
                input("Press Enter to receive...")
                c = Node()
                print(c.receive())

    except getopt.GetoptError:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
