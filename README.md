# peerbook

peerbook is A WebRTC signaling server with a private address book for
passwordless-users and their WebRTC peers.
peerbook is written in golang and using the great code from
gomodule/redigo and gorilla/websocket.

peerbook server lets users store and retrieve a list of peers.
Each peer has a name, a fingerprint, a kind, an online flag and a verified flag.

Upon connection request, 
peerbook exchanges the fingerprints so peers can ensure the peer's fingerprint
is used to encrypt's the peer connection (TODO: add link to example).
Once keys are exchanged, ICE candidates should start trickling, with
peerbook forwarding candidates ASAP.

## Peer Identity

To create a list of authorized peers peerbook requires clients to provide a
fingerprint. It is recommended to use the one used to secure the Peer
Connection. Fingerprints have to be persistent so peers need to save their
certificate in a persistent storage. In the browser it's a bit complicated
as one has to use IndexDB. Here's a code sample for the browser and here's one
for pion/webrtc.

## Verifying a peer

When a peer wishes to test whether its fingerprint is verified or no, 
it POSTs to `/verify` with a json encoded onject in the body.
A valid bodyd have the `fp` and `email` fields.

If peerbook finds 
## Intiating a connection

Upon launch, peers should start a websocket connection at:
`/ws` with the `fp` query parameter containing the peer's fingerprint

Upon receiving the request peerbook compares the peer's fingerprint & name
with user's peer list.
If all is well, peerbook will send a 200 messages and listen for 
connection requests over the established websocket.

If the peer is unknown, or known with a diferent fingerprint, peerbook 
will keep the connection open and send a 401 messages. 
In another thread, peerbook will email the user a short-lived link.
Clicking the link leads the user to a page with the list of peers
and new requests. The user can choose what changes to make and update his
lists.

## Verifying a peer

Once it has a fingerprint and an email a program can verify it's fingerprint
by POSTing to `/verify` with a body as in:

```json
{
    "fp": "<>",
    "email": "jrandomhacker@nowhere.org"
}
```

peerbook will reply with a message:

```json
{
    "verified": false
}
```

If the peer is indeed not verified peerbook sends and email to the user
letting him add the peer to his peerbook.


## Getting the peer list

When a peer needs the user's list of peers it sends a `get_list` command:

```json
{
    "command": "get_list"
}
```

to which peerbook will reply with:

```json
{
    "peers": [
     {"name": "<>", 
     "fp": "<>",
     "kind": "<>",
     "created_on": "<>",
     "last_seen": "<>",
     "verified_on": "<>"
     }]
 }
 ```
## The Connection Flow

To request a connection, a peer sends a request to peerbook. If it supports
trickle ICE the peer sends the request as often as he gets new candidates:

```json
{
    "target": "<peer's fingerprint>",
    "offer": "<encoded offer>"
}
```

peerbook will look for the target peer. If found, peerbook does two things:
- send the target a connection request:
    ```json
    {
        "source_fp": "<initiator's fingerprint>",
        "source_name": "<initiator's name>",
        "offer": "<encoded offer>"
    }
    ```

Upon receiving the message the peer will set the remote description,
start collencting answers and stream the candidates as it gets them.

```json
{
    "target": "<initiaotr's fingerprint>",
    "answer": "<encoded answer>"
}
```

peerbook uses the `target` field to identify the connection request and
forward the answer to the initiator:

```json
{
    "source_fp": "<sender's fingerprint>",
    "source_name": "<initiator's name>",
    "answer": "<encoded answer>"
}
```

## Storing peers

Each user has a list of peer names and fingerprints.
It is all stored in Redis, where the keys are the users' email 
each with values a list of strings, one for each peer in the format 
`<name>:<fingerprint>:`.

