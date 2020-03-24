#!/usr/bin/python3

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
from node import Node
from utils import OK, Verifier, aes_encode, TIME, generate_nonce, verify_nonce, TIMEOUT, ERROR, MESSAGE_OK

# the evil node does not have K_AB
CYCLES = 10  # to make the key arbitrary long


class EvilNode(Node):
    """
    EvilNode class.
    For simplicity, it implements only the 2-phase-loop.
    We assume that the EvilNode has already the encrypted information from A and B.
    We implement the receiver (B side) evil version of the Node. Which means that this script will maintain the
    K_AB valid for more than it is allowed to.

    process flow:
    ( 1 ) A --> T(S): A, {T_A, B, K_AB}K_AS	        T intercept the message, T has A
    ( 2 ) T(A) --> S: A, {T_A, B, K_AB}K_AS	        Resend same message fast enough
    ( 3 ) S --> T(B): {T_S, A, K_AB}K_BS		    T intercepts message for B
    ( 4 ) T(B) --> S: B, {T_S, A, K_AB}K_BS	        fast enough		                    1. Loop <--
    ( 5 ) S --> T(A): {T_Su, B, K_AB}K_AS		    Timestamp is updated	            2. Loop <--
    ( 6 ) T(A) --> S: A, {T_Su, B, K_AB}K_AS	    Final request
    ( 7 ) S --> B: {T_Su, A, K_AB}K_BS   		    K_AB is expired
    """

    def __init__(self):
        super().__init__()
        self.message = {}  # saved the message to be sent

    def send(self):
        """
        send the message B, {T_S, A, K_AB}K_BS where the encrypted part is what the server sent
        :return:
        """
        self.id = 'B'  # identity
        to_send = self.message
        to_send['dest'] = 'send'
        to_send['sender'] = self.id
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        return data

    def receive(self):
        """
        receive message in step ( 3 ) -- node is T(B).
        Then the loop ( 4 ) - ( 5 ) starts.
        Message received: {T_S, A, K_AB}K_BS
        :return:
        """
        to_send = {'dest': 'recv'}
        self.nodesocket.sendall(pickle.dumps(to_send))
        data = pickle.loads(self.nodesocket.recv(MAX_SIZE))
        self.message = data


def main():
    """
    - the evil node will receive the message that was supposed to be for B.
    - it creates a cycle which send / receive and makes S to update the timestamp
    - they key K_AB appears to be valid even after the timeout
    """
    e = EvilNode()
    for i in range(0, CYCLES):
        e.receive()
        _ = e.send()
        time.sleep(2)


if __name__ == "__main__":
    main()
