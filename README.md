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
<!--- 
These libraries are listed in the `requirements.txt` file. So the only command you need to run is:
```bash
pip install -r requirements.txt
```

However, if you want to install single package just use:
```bash
❯ pip install pycryptodome
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
├── [3.1K]  README.md
└── [ 16K]  src
    ├── [3.4K]  evil_node.py
    ├── [2.8K]  node.py
    ├── [4.8K]  server.py
    └── [2.1K]  utils.py
```
* The `node.py` script implements an honest node, sharing `K` with `S`;
* The `evil_node.py` implements an instance of `E`, and even if it does not
share the same `K` with `S`, it makes `S` believe it does;
* `utils.py` contains some useful functions shared by both parties;
* `server.py` implements the party that makes sure a new node has the shared `K`. Hence
gives an approval or a denial to the connecting node `N`.

## Running
To run the scripts open two different sessions, node and server.
In the server session:
```bash
❯ python server.py
Listening on: 127.0.0.1:8300
... waiting for a connection
```
In the node session:
```bash
❯ python node.py
The message is authentic!
CONGRATULATIONS, YOU ARE VERIFIED!
```
And the result back in the server session:
```bash
Got a connection from ('127.0.0.1', 64756)
New connection added:  ('127.0.0.1', 64756)
Connection from :  ('127.0.0.1', 64756)
The message is authentic!
Client at  ('127.0.0.1', 64756)  disconnected...
```

### Running without K

If the node does not share the same key `K`, then the outcome is in node session:

```bash
❯ python node.py
ERROR: Server Key is not verified!
Key incorrect or message corrupted!
ERROR: Ah-ah-ah! You didn't say the magic word!
```
While in the server session:
```bash
Got a connection from ('127.0.0.1', 65113)
New connection added:  ('127.0.0.1', 65113)
Connection from :  ('127.0.0.1', 65113)
Key incorrect or message corrupted!
Client at  ('127.0.0.1', 65113)  disconnected...
```
--->
## Authors

* **Enrico Tedeschi** - *Initial work* - [reflection_attack](https://github.com/ted92/key_exchange_attack)
