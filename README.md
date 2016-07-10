[![Build Status](https://travis-ci.org/piranna/nodeos-reverse-proxy.svg?branch=master)](https://travis-ci.org/piranna/nodeos-reverse-proxy)

NodeOS Reverse Proxy
====================

Reverse proxy for NodeOS based on the users accounts and passwords. It also
allow to register domains for specific HTTP and WebSocket servers defined by the
users, and ports for a NAT-like functionality. Registering of domains and ports
is done by HTTP POST requests, that can be easily managed by using the module
[nodeos-reverse-proxy-register](https://github.com/piranna/nodeos-reverse-proxy-register)
