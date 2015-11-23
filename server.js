#!/usr/bin/env node

var http  = require('http')
var parse = require('url').parse
var spawn = require('child_process').spawn

var createProxyServer = require('http-proxy').createProxyServer
var finalhandler      = require('finalhandler')


var port = 80


var user2proxy = {}

function getAuth(url)
{
  var auth = parse(url).auth
  if(!auth) return

  // Get user and passwrod
  var pass = auth.split(':')
  var user = pass.shift()
  pass = pass.join(':')

  return {user: user, pass: pass}
}

function getProxy(user, callback)
{
  var proxy = user2proxy[user]
  if(proxy) return callback(null, proxy)

  var options =
  {
    cwd: '/home/nodeos',
    env:
    {
      PATH: '/bin'
    }
//    uid:
//    gid:
  }

  var cp = spawn('oneshoot', [], options)

  cp.on('error', callback)

  cp.stdout.once('data', function(data)
  {
    var options =
    {
      target:
      {
        host: 'localhost',
        port: parseInt(data)
      }
    }

    user2proxy[user] = proxy = createProxyServer(options)

    cp.on('exit', function()
    {
      delete user2proxy[user]
      proxy.close()
    })

    callback(null, proxy)
  })
}


var server = http.createServer()


// HTTP
server.on('request', function(req, res)
{
  console.log(req.headers)
  var done = finalhandler(req, res)

  var auth = getAuth(req.url)
  if(!auth) return done()

  var user = auth.user
  if(!user) return done()

  getProxy(user, function(error, proxy)
  {
    if(error) return done(error)

    proxy.web(req, res)
  })
})


// WebSockets
server.on('upgrade', function(req, socket, head)
{
  var done = socket.end.bind(socket)

  var auth = getAuth(req.url)
  if(!auth) return done()

  var user = auth.user
  if(!user) return done()

  getProxy(user, function(error, proxy)
  {
    if(error) return done()

    proxy.ws(req, socket, head)
  })
})


// Start server
server.listen(port)
