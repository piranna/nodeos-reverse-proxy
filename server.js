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


var user2proxy = {}
var user2cp = {}

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

function validateUser(auth, callback)
{
  // Get user's $HOME directory
  var home = '/home/'+auth.name

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

      try
      {
        if(statsHome.uid !== uid || statsHome.gid !== gid)
          return callback(home+" uid & gid don't match with its logon config file")

        var config = require(logon)
      }
      catch(error)
      {
        return callback(error)
      }

      var password = config.password

      // User don't have defined a password, it's a non-interactive account
      if(typeof password !== 'string')
        return callback('Non-interactive account')

      // Check if account is password-less (for example, a guest account)
      // or it's the correct one
      if(password !== ''
      && password !== crypto.createHash('sha1').update(auth.pass).digest('hex'))
        return callback('Invalid password')

      callback(null, {uid: uid, gid: gid, config: config, home: home})
    })
  })
}


function startUserServer(argv, cwd, name)
{
  function deleteUser2cp()
  {
    delete user2cp[name]
  }

  var cp = spawn(__dirname+'/chrootKexec.js', argv, {cwd: cwd})

  cp.once('error', deleteUser2cp)

  cp.stdout.once('data', function(data)
  {
    deleteUser2cp()
    cp.removeListener('error', deleteUser2cp)

    var options =
    {
      target:
      {
        host: LOCALHOST,
        port: parseInt(data.toString())
      }
    }

    user2proxy[name] = proxy = createProxyServer(options)

    cp.on('exit', function(code, signal)
    {
      delete user2proxy[name]
      proxy.close()
    })

    proxy.on('error', function(error)
    {
      delete user2proxy[name]
      cp.kill('SIGTERM')
    })
  })

  return cp
}


function getProxy(auth, callback)
{
  var name = auth.name

  var proxy = user2proxy[name]
  if(proxy) return callback(null, proxy)

  validateUser(auth, function(error, validation)
  {
    if(error) return callback(error)

    var config = validation.config

    var argv =
    [
      validation.uid, validation.gid,
      config.guiServer,
      '--hostname', LOCALHOST,
    ]

    if(config.shell)
      argv = argv.concat('--command', config.shell, '--', config.shellArgs || [])

    var cp = user2cp[name]
    if(!cp) user2cp[name] = cp = startUserServer(argv, validation.home, name)

    cp.once('error', callback)

    cp.stdout.once('data', function()
    {
      cp.removeListener('error', callback)

      callback(null, proxy)
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
  if(!auth || !auth.name) return end()

  getProxy(auth, function(error, proxy)
  {
    if(error) return end(error)

    proxy.ws(req, socket, head)
  })
})


// Start server
server.listen(port)
