#!/usr/bin/python3

__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT, HOST, aes_decode
import socket
import sys
import getopt
import pickle
import time
from datetime import datetime
from utils import OK, Verifier, aes_encode, TIME, generate_nonce, verify_nonce

SHARED_KEY_SERVER = b'TheForceIsStrong'  # 16bit AES key
SHARED_KEY = b'!ThePathIsClear!'
TIMESTAMP = 5  # seconds allowed for a key to be valid during the transmission of a message


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
        self.timestamp = TIMESTAMP
        self.id = None

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
        self.id = 'A'  # identity
        self.timestamp = datetime.now()  # set the timestamp
        to_encrypt = {'timestamp': self.timestamp, 'rcv': 'B', 'key': self.aes}  # T_A, B, K_AB
        n, ciphertext, tag = aes_encode(self.aes_server, pickle.dumps(to_encrypt))  # {T_A, B, K_AB}K_AS
        # destination is 'first', being this the first step of the protocol
        to_send = {'dest': 'first', 'sender': self.id, 'n': n, 'c': ciphertext, 't': tag}  # A, {T_A, B, K_AB}K_AS
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data

    def receive(self):
        """
        receive message in step ( 2 ) -- node is B
        :return:
        """
        # todo: define receive
        # todo: server part
        # todo: implement a waiting cycle in the node.

    def final_proof(self, data):
        """
        send the final proof back, server nonce in plaintext
        :param data:    dict, data received from the server
                        {   'n_n'   : N_N,
                            'n'     : nonce_encryption,
                            'c'     : ciphertext,
                            't'     : tag }
        ( 3 ) step three of the algorithm
        """
        n = data['n']
        c = data['c']
        t = data['t']
        n_s = aes_decode(n, c, t, self.aes)
        to_send = {'id': self.id, 'dest': 'confirmation', 'n': n_s}
        print(Colors.BOLD + 'N --> S: N_S' + Colors.ENDC)
        print('\t' + Colors.BOLD + 'N_S: ' + Colors.ENDC + str(n_s))
        self.nodesocket.sendall(pickle.dumps(to_send))
        data_return = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data_return


def main(argv):
    try:
        _, _ = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("node.py -p <file_path>")
        sys.exit(2)
    c = Node()
    data = c.setup()  # data should contain the step ( 2 ) of the algorithm
    # { 'n_n': N_N, 'n': nonce_encryption, 'c': ciphertext, 't': tag }
    n_n = data['n_n']
    if verify_nonce(n_n, c.nonce):
        # if server verified the nonce, then continues with step ( 3 )
        data = c.final_proof(data)
        print(data)
    else:
        print("ERROR: Server Key is not verified!")
        data = c.final_proof(data)
        print(data)


if __name__ == "__main__":
    main(sys.argv[1:])
