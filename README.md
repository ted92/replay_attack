# Replay Attack
Implementation in Python of a replay attack, performed during a communication between
two parties and a central trusted authority.

## Getting Started - Protocol
The following protocol allows a client `A` to suggest a shared key `K_AB` for
communicating with `B` rather than depending on a server to generate that key.
So server `S` is used in the protocol only as a secure communications channel
from `A` to `B`, because:
* `K_AS` is shared between `A` and `S`
* `K_BS` is shared between `B` and `S`

Assume that principals `A`, `B`, and `S`
ignore any message they receive that contains a timestamp that is more than 5 seconds old.


```
A --> S:  A, {T_A, B, K_AB}K_AS     where T_A is current time
S --> B:  {T_S, A, K_AB}K_BS   	    where T_S is current time
```

However, this protocol is flawed. An intruder `T` can force `B` to adopt an 
instance of `K_AB` that is arbitrarily old. 

### Replay Attack

The attack is performed through a man in the middle,
exploiting the fact that the receiver is sent in plaintext.
We can refer to it is as a replay attack (or playback attack).
`A` malicious party, `T`, will stand in between the communication
from `A`, `B` and `S`. In this way, if the attack is performed fast
enough, it could trick `S` and make it to rewrite the timestamp even
though the key is arbitrary old. Here follows an example of the attack:

```
A --> T(S): A, {T_A, B, K_AB}K_AS	    T intercept the message, T has A
T(A) --> S: A, {T_A, B, K_AB}K_AS	    Resend same message fast enough
S --> T(B): {T_S, A, K_AB}K_BS		    T intercepts message for B
T(B) --> S: B, {T_S, A, K_AB}K_BS	    fast enough		         1. Loop <- 
S --> T(A): {T_Su, B, K_AB}K_AS		    Timestamp is updated	 2. Loop <-
T(A) --> S: A, {T_Su, B, K_AB}K_AS	    Final request
S --> B: {T_Su, A, K_AB}K_BS   		    K_AB is expired
```
The loop between 1. and 2. makes the key `K_AB` arbitrarily old.


### Prerequisites

Libraries used, you might require to install:
1. pycryptodome
2. websocket
3. websocket-client

These libraries are listed in the `requirements.txt` file. So the only command you need to run is:
```bash
pip install -r requirements.txt
```

However, if you want to install single package just use:
```bash
❯ pip install <package_name>
```

To check you comply with the requirements you can check with:
```bash
❯ pip check
No broken requirements found.
```

### Scripts
The scripts and folders are the following:
```
.
├── [4.2K]  README.md
├── [  40]  requirements.txt
└── [ 14K]  src
    ├── [2.7K]  evil_node.py
    ├── [3.8K]  node.py
    ├── [4.8K]  server.py
    └── [2.6K]  utils.py
```

* The `node.py` script implements an honest node, which wants to share a key `K_AB` through
`S`, with `A` and `B`;
* The `evil_node.py` implements an instance of `T`, and its purpose is to make the server
`S` to keep extending the timestamp for which `K_AB` is valid;
* `utils.py` contains some useful functions shared by both parties;
* `server.py` implements a trusted authority `S`.

## Running Honestly
To run the scripts open three different sessions, sender, receiver and server.
In the server session:
```bash
❯ python server.py
Listening on: 127.0.0.1:8300
... waiting for a connection
```
In the sender session, the default key or a new personalized one can be used.
While the receiver session makes the node ready to listen the message with the
key from the server.
```
p node.py   [-s]                : send mode
            [-k] <binary_key>   : set the binary key to send
            [-r]                : receive mode
```
Run first the sender session then press Enter to send the key at the time you decide.
```bash
❯ python node.py -s
Press Enter to send...
Timestamp is valid
```

To receive the message, before the timestamp will expire, in the receiver session:
```bash
❯ python node.py -r
Press Enter to receive...
The message is authentic!
Timestamp is valid
```
If you run the script after the timeout we set, then you get this:
```bash
❯ python node.py -r
Press Enter to receive...
TIMESTAMP NOT VALID!
```

## Running Evil Node
Due to the faults in the server protocol, it is possible make the timestamp valid
even if the key shared by the two parties is arbitrary old. If the evil node is performed
fast enough (before the timeout), then it is possible to extend the validity of the key.
* Run the server;
* Run the node and send the message;
* Run the evil node in another session:
```bash
python evil_node.py
```
* Run the receiver, fast enough (before the timeout from the end of the evil_node script).

## Authors

* **Enrico Tedeschi** - *Initial work* - [reflection_attack](https://github.com/ted92/replay_attack)
