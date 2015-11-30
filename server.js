#!/usr/bin/env node

var crypto   = require('crypto')
var http     = require('http')
var parse    = require('url').parse
var spawn    = require('child_process').spawn
var stat     = require('fs').stat

var basicAuth         = require('basic-auth')
var createProxyServer = require('http-proxy').createProxyServer
var finalhandler      = require('finalhandler')


const LOCALHOST = '127.0.0.1'


var port = process.argv[2] || 80

var users = {}


function getAuth(req)
{
  // Url
  var auth = parse(req.url).auth
  if(auth)
  {
    // Get name and pass
    var pass = auth.split(':')
    var name = pass.shift()
    pass = pass.join(':')

    return {name: name, pass: pass}
  }

  // Header
  return basicAuth(req)
}

function checkPassword(password, hash)
{
  // User don't have defined a password, it's a non-interactive account
  if(typeof hash !== 'string') return 'Non-interactive account'

  // Check if account is password-less (for example, a guest account)
  // or it's the correct one
  if(hash !== ''
  && hash !== crypto.createHash('sha1').update(password).digest('hex'))
    return 'Invalid password'
}

function getUser(auth, callback)
{
  var name = auth.name

  var user = users[name]
  if(user)
  {
    var error = checkPassword(auth.pass, user.config.password)
    if(error) return callback(error)

    return callback(null, user)
  }

  // Get user's $HOME directory
  var home = '/home/'+name

  stat(home, function(error, statsHome)
  {
    if(error) return callback(error)

    // Get user's logon configuration
    var logon = home+'/etc/logon.json'

    stat(logon, function(error, stats)
    {
      if(error) return callback(error)

      var uid = stats.uid
      var gid = stats.gid

      if(statsHome.uid !== uid || statsHome.gid !== gid)
        return callback(home+" uid & gid don't match with its logon config file")

      try
      {
        var config = require(logon)
      }
      catch(error)
      {
        return callback(error)
      }

      var password = config.password
      var error = checkPassword(auth.pass, password)
      if(error) return callback(error)

      users[name] = user =
      {
        config:   config,
        gid:      gid,
        home:     home,
        password: password,
        uid:      uid
      }

      callback(null, user)
    })
  })
}

function startUserServer(user)
{
  var config = user.config

  var argv =
  [
    user.uid, user.gid,
    config.guiServer,
    '--hostname', LOCALHOST,
  ]

  if(config.shell)
    argv = argv.concat('--command', config.shell, '--', config.shellArgs || [])

  user.server = server = spawn(__dirname+'/chrootKexec.js', argv, {cwd: cwd})

  var options =
  {
    target:
    {
      host: LOCALHOST,
      port: parseInt(data.toString())
    }
  }

  var proxy = createProxyServer(options)

  server.stdout.once('data', function(data)
  {
    user.proxy = proxy

    server.on('exit', function(code, signal)
    {
      delete users[name]
      proxy.close()
    })

    proxy.on('error', function(error)
    {
      delete users[name]
      server.kill('SIGTERM')
    })
  })

  return server
}

function getProxy(auth, callback)
{
  getUser(auth, function(error, user)
  {
    if(error) return callback(error)

    var proxy = user.proxy
    if(proxy) return callback(null, proxy)

    var server = user.server
    if(!server)
      user.server = server = startUserServer(user)

    server.once('error', callback)
    server.stdout.once('data', function()
    {
      server.removeListener('error', callback)

      callback(null, user.proxy)
    })
  })
}


// Create server to lister for HTTP and WebSockets connections
var server = http.createServer()


// HTTP
server.on('request', function(req, res)
{
  var auth = getAuth(req)
  if(!auth || !auth.name)
  {
    res.statusCode = 401
    res.setHeader('WWW-Authenticate', 'Basic realm="Welcome to NodeOS!"')

    return res.end()
  }

  getProxy(auth, function(error, proxy)
  {
    if(error) return finalhandler(req, res)(error)

    proxy.web(req, res)
  })
})


// WebSockets
server.on('upgrade', function(req, socket, head)
{
  var end = socket.end.bind(socket)

  var auth = getAuth(req)
  if(!auth || !auth.name) return end()

  getProxy(auth, function(error, proxy)
  {
    if(error) return end(error)

    proxy.ws(req, socket, head)
  })
})


// Start server
server.listen(port)
