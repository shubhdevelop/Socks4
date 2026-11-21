# SOCKS4 Implementation

This is an honest implementation of SOCKS4 and SOCKS4a (an extension to the original with support for resolving destinations by domain name)
proxy; this is by no means meant for production use, **YET** :D

Currently doesn't properly handle the error replies.

It can be used for personal use though. One use case I can think of is running several services behind a Cloudflare
or ngrok tunnel and only exposing the proxy, since they let you create a tunnel on a single port on a free account.

This project supports both SOCKS4 commands, CONNECT and BIND.

## Build

```bash
make socks4
./socks4 [bind-address] [port]   # default 127.0.0.1:1080
```

Linux with `liburing` is required. Optional: `make webapp` for a local test UI.

## Supported Commands

CONNECT lets you connect to a port on some IP behind the proxy, discovers the
service for you, and sets up a relay.

BIND lets you open a port on the proxy and start listening on that port.
You provide the peer's IP address and port 0.
Once a peer with the same IP address connects, the proxy sets up the relay and forwards traffic
from the peer to the initial client, acting as an inward proxy. The proxy only lets the advertised tuple
(request IP and opened port) connect to the port requested in the BIND command.

This is only written as a learning project in order to understand basics of networking, frame parsing, network protocol branch handling, and Linux's `io_uring`.

## Client

The work on the client is in progress. Essentially the plan is: if the handshake and relay setup goes as expected, the client will return a raw socket
and some utilities to write on top of that raw TCP socket so that other applications can use it; the client would be a wrapper on top of send and recv.