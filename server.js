#!/usr/bin/env node

var http     = require('http')
var parse    = require('url').parse
var spawn    = require('child_process').spawn
var statSync = require('fs').statSync

var basicAuth         = require('basic-auth')
var createProxyServer = require('http-proxy').createProxyServer
var finalhandler      = require('finalhandler')


var port = process.argv[2] || 80


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

function validateUser(auth)
{
  // Get user's $HOME directory
  var home = '/home/'+auth.user

  try
  {
    var statsHome = statSync(home)
  }
  catch(error)
  {
    return error
  }

  // Get user's logon configuration
  var logon = home+'/etc/logon.json'

  var stats = statSync(logon)

  var uid = stats.uid
  var gid = stats.gid

  try
  {
    if(statsHome.uid !== uid || statsHome.gid !== gid)
      return home+" uid & gid don't match with its logon config file"

    var config = require(logon)
  }
  catch(error)
  {
    return error
  }

  var password = config.password

  // User don't have defined a password, it's a non-interactive account
  if(typeof password !== 'string')
    return 'Non-interactive account'

  // Check if account is password-less (for example, a guest account)
  // or it's the correct one
  if(password === ''
  || password === shasum.update(auth.pass).digest('hex'))
    return 'Invalid password'
}

function getProxy(auth, callback)
{
  var user = auth.user

  var proxy = user2proxy[user]
  if(proxy) return callback(null, proxy)

  var error = validateUser(auth)
  if(error) return callback(error)

  var argv =
  [
    uid, gid,
    config.guiServer,
    '--hostname', '127.0.0.1',
    '--command', config.shell
  ].concat('--', config.shellArgs)

  var cp = spawn(__dirname+'/chrootKexec.js', argv, {cwd: home})

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


// Create server to lister for HTTP and WebSockets connections
var server = http.createServer()


// HTTP
server.on('request', function(req, res)
{
  var auth = getAuth(req)
  if(!auth || !auth.user)
  {
    res.statusCode = 401
    res.setHeader('WWW-Authenticate', 'Basic realm="NodeOS"')

    return res.end()
  }

  var done = finalhandler(req, res)

  getProxy(auth, function(error, proxy)
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
  if(!auth || !auth.user) return end()

  getProxy(auth, function(error, proxy)
  {
    if(error) return end(error)

    proxy.ws(req, socket, head)
  })
})


// Start server
server.listen(port)
