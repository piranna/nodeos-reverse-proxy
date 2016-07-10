#!/usr/bin/env node

const http = require('http')

const ReverseProxy = require('.')


const reverseProxy = ReverseProxy()

// Create server to lister for HTTP and WebSockets connections
var server = http.createServer()

// HTTP and WebSockets connections
server.on('request', reverseProxy.onRequest)
server.on('upgrade', reverseProxy.onUpgrade)

// Start server
server.listen(process.argv[2] || 80)
