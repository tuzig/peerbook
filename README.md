# peerbook

> WIP: This is just a plan, nothing to use yet

peerbook is A WebRTC signaling server with an address book for
passwordless-users and their WebRTC peers. It's based on websockets, redis and
gorilla/websocket.

peerbook server lets users store and retrieve a list of trusted peers,
their fingerprints and any other properties the app wishes to store.
For example, a terminal app can add a `kind` key with the values of `client`
and `server` so the client can filter list and display only servers.

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

## Intiating a connection

Upon launch, peers should start a websocket connection at:
`/ws` with the following query parameters:

- `email` - the user's email
- `name` - peer's name
- `fingerprint` - the peer's fingerprint
- `kind` - the peer's type

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

## Getting the peer list

When a peer needs the user's list of peer it sends a `get_list` command:

```json
{
    "command": "get_list"
}
```

to which peerbook will reply with:

```json
{
    "list": [
     {"name": "<>", 
     "fingerprint": "<>",
     "resgitration_date": "<>",
     "last_connection": "<>",
     "kind": "<>"
     }]
 }
 ```
## The Connection Flow

To request a connection, a peer sends a request to peerbook. If it supports
trickle ICE the peer sends the request as he gets new candidates:

```json
{
    "target": "<peer name>",
    "offer": "<encoded offer>"
}
```

peerbook will look for the target peer. If found, peerbook does two things:
- send the target a connection request:
    ```json
    {
        "source": "<initiator's name>",
        "fingerprint": "<initiator's fingerprint>",
        "offer": "<encoded offer>"
    }
    ```

Upon receiving the message the peer will set the remote description,
start collencting answers and stream the candidates as it gets them.

```json
{
    "target": "<initiaotr's name>",
    "fingerprint": "<initiator's fingerprint>",
    "answer": "<encoded answer>"
}
```

peerbook uses the `fingerprint` field to identify the connection request and
forward the answer to the initiator:

```json
{
    "source": "<target's name>",
    "fingerprint": "<target's fingerprint>",
    "answer": "<encoded answer>"
}
```

## Storing peers

Each user has a list of peer names and fingerprints.
It is all stored in Redis, where the keys are the users' email 
each with values a list of strings, one for each peer in the format 
`<name>:<fingerprint>:`.

