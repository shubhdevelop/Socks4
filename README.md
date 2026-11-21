# SOCKS4 Implmentation

This is a honest implementation of SOCKS4 and SOCKS4a (an extension to the original with support lookup by domain name)
proxy, this by no means meant for production use, **YET** :D

It can be used for personal use, one use case I can thing of is running several services behind the cloudflare
or ngrok tunnel and only exposing the proxy as ngrok only provide single connection on
free account.

This is only written as learning project in order to understand basics of network
frame parsing, and network protocol branching, and Linux's `io_uring`.

This Project supports both SOCKS4 commands, CONNECT and BIND.

CONNECT command let's you connect to a port on some IP behind the proxy, it discovers the
services for you, and setups a relay.

BIND command let's you open a port on the proxy and start listening on that port. you provide the IP address peer, once
the peer with same IP address connects, it setups the relay proxy forwards all the traffic from peer to the client, acting as
as inward proxy. Proxy only let's the advertised IP to be able connect to the in to the BIND opened port.
