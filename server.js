#!/usr/bin/env node

var http  = require('http')
var parse = require('url').parse
var spawn = require('child_process').spawn

var basicAuth         = require('basic-auth')
var createProxyServer = require('http-proxy').createProxyServer
var finalhandler      = require('finalhandler')


var port = 80


var user2proxy = {}

function getAuth(req)
{
  // Url
  var auth = parse(req.url).auth
  if(auth)
  {
    // Get user and passwrod
    var pass = auth.split(':')
    var user = pass.shift()
    pass = pass.join(':')

    return {user: user, pass: pass}
  }

  // Header
  return basicAuth(req)
}

function getProxy(user, callback)
{
  var proxy = user2proxy[user]
  if(proxy) return callback(null, proxy)

  var argv =
  [
    uid, gid,
    'oneshoot',
    '--hostname', '127.0.0.1',
    '--command', config.command
  ].concat('--', config.shellArgs)

  var options =
  {
    cwd: '/home/'+user,
  }

  var cp = spawn(__dirname+'/chrootKexec.js', argv, options)

  cp.once('error', callback)

  cp.stdout.once('data', function(data)
  {
    cp.removeListener('error', callback)

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
  function realm()
  {
    res.statusCode = 401
    res.setHeader('WWW-Authenticate', 'Basic realm="NodeOS"')
    res.end()
  }

  var auth = getAuth(req)
  if(!auth) return realm()

  var user = auth.user
  if(!user) return realm()

  var done = finalhandler(req, res)

  getProxy(user, function(error, proxy)
  {
    if(error) return done(error)

    proxy.web(req, res)
  })
})


// WebSockets
server.on('upgrade', function(req, socket, head)
{
  var end = socket.end.bind(socket)

  var auth = getAuth(req)
  if(!auth) return end()

  var user = auth.user
  if(!user) return end()

  getProxy(user, function(error, proxy)
  {
    if(error) return end(error)

    proxy.ws(req, socket, head)
  })
})


// Start server
server.listen(port)
