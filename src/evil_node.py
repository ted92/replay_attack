#!/usr/bin/python3

# todo: implement evil node
__author__ = "Enrico Tedeschi"
__copyright__ = "Copyright 2020, Arctic University of Norway"
__email__ = "enrico.tedeschi@uit.no"

from utils import Colors, MAX_SIZE, PORT, HOST, aes_decode
from node import Node
import socket
import sys
import getopt
import pickle
import time
from utils import OK, Verifier, aes_encode, TIME, generate_nonce, verify_nonce

KEY = b'TheForceIsString'  # 16bit AES key


class ENode(Node):
    """
    Node class which performs a REFLECTION ATTACK
    process flow:
    ( 1 )   E --> S: N_E							    .1
    ( 2 )   S --> E: {N_S}K, {N_E}_DECRYPTED_WITH_K	    .1
    ( 3 )   E --> S: {N_S}K							    .2
    ( 4 )   S --> E: {N_S2}, N_S					    .2
    ( 5 )   E --> S: N_S							    .1

    """

    def setup(self, n='', ciphertext='', tag=''):
        """
        :param n: fixed nonce
        :param ciphertext: fixed ciphertext
        :param tag: fixed tag
        nonce creation and setup with the server.
        ( 1 ) step one of the algorithm
        """
        self.nonce = generate_nonce()
        if n == '':
            n, ciphertext, tag = aes_encode(self.aes, self.nonce)
        to_send = {'dest': 'setup', 'n': n, 'c': ciphertext, 't': tag}  # dictionary to send to the server
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        self.id = data['id']  # set the given id from the server
        return data

    def final_proof(self, data, n_s=''):
        """
        send the final proof back, server nonce in plaintext
        :param data:    dict, data received from the server
                        {   'n_n'   : N_N,
                            'n'     : nonce_encryption,
                            'c'     : ciphertext,
                            't'     : tag }
        :param n_s: nonce of the server already fetched
        ( 3 ) step three of the algorithm
        """
        if n_s == '':
            n = data['n']
            c = data['c']
            t = data['t']
            n_s = aes_decode(n, c, t, self.aes)
        to_send = {'id': self.id, 'dest': 'confirmation', 'n': n_s}
        self.nodesocket.sendall(pickle.dumps(to_send))
        data_return = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data_return


def main(argv):
    try:
        _, _ = getopt.getopt(argv, "p:", ["path="])
    except getopt.GetoptError:
        print("node.py -p <file_path>")
        sys.exit(2)
    c1 = ENode()  # first session open
    data = c1.setup()  # data should contain the step ( 2 ) of the algorithm
    n = data['n']
    c = data['c']
    t = data['t']
    # { 'n_n': N_N, 'n': nonce_encryption, 'c': ciphertext, 't': tag }
    c2 = ENode()
    data = c2.setup(n, c, t)
    n_n = data['n_n']
    if not verify_nonce(n_n, c1.nonce):
        print("ERROR: Server Key is not verified!")
        # if server verified the nonce, then continues with step ( 3 )
    data = c1.final_proof(data, n_n)  # n_n now is the "n_s" in plaintext since the server decrypted it
    print(data)


if __name__ == "__main__":
    main(sys.argv[1:])
