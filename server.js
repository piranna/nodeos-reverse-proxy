#!/usr/bin/env node

var crypto = require('crypto')
var http   = require('http')
var parse  = require('url').parse
var spawn  = require('child_process').spawn
var stat   = require('fs').stat

var basicAuth         = require('basic-auth')
var concat            = require('concat-stream')
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
  if(typeof hash !== 'string') return 403

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
        config: config,
        gid:    gid,
        home:   home,
        name:   name,
        uid:    uid
      }

      callback(null, user)
    })
  })
}

function startUserServer(user)
{
  var argv =
  [
    user.uid, user.gid,
    user.config.guiServer,
    '--hostname', LOCALHOST,
  ]

  var server = spawn(__dirname+'/chrootKexec.js', argv, {cwd: user.home})

  server.stdout.once('data', function(data)
  {
    var options =
    {
      target:
      {
        host: LOCALHOST,
        port: JSON.parse(data)
      }
    }

    var proxy = createProxyServer(options)
    user.proxy = proxy

    var name = user.name

    server.on('exit', function(code, signal)
    {
      delete users[name]
      proxy.close()
    })

    proxy.on('error', function(error)
    {
      delete users[name]
      server.kill()
    })
  })

  return server
}

function checkOutput(server, callback)
{
  function disconnect()
  {
    server.removeListener('error', onError)
    server.removeListener('exit' , onExit )

    server.stdout.removeListener('data', onData)
    server.stderr.unpipe(process.stderr)
  }

  function onError(error)
  {
    disconnect()
    callback(error)
  }
  function onExit(code)
  {
    disconnect()
    callback(new Error('Server exited before providing its port'))
  }
  function onData()
  {
    disconnect()
    callback()
  }

  server.once('error', onError)
  server.once('exit' , onExit )

  server.stdout.once('data', onData)
  server.stderr.pipe(process.stderr)
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

    // Check execution of server
    checkOutput(server, function(error)
    {
      if(error) return callback(error)

      callback(null, user.proxy)
    })
  })
}


const domains = {}
const ports   = {}

function register(req, res)
{
  const final = finalhandler(req, res)

  if(req.headers.host !== '127.0.0.0') return final(403)

  req.pipe(concat(function(data)
  {
    data = JSON.parse(data)

    const port = data.port
    if(!port) return final(422)

    const domain = data.domain
    const externalPort = data.externalPort
    if(domain)
    {
      var entry = domains[domain]
      if(!entry)
        domains[domain] = entry =
        {
          token: uuid(),
          port: port
        }
      else if(entry.token !== data.token) return final(422)

      entry.domain = domain
      res.end(token)
    }
    else if(externalPort)
    {
      // Don't register unpriviledged ports since they van be used directly
      if(externalPort >= 1024) return final(422)

      var entry = ports[externalPort]
      if(!entry)
        ports[externalPort] = entry =
        {
          token: uuid(),
          port: port
        }
      else if(entry.token !== data.token) return final(422)

      entry.externalPort = externalPort
      res.end(token)
    }
    else return final(422)
  }))
}

function unregister(req, res)
{
  const final = finalhandler(req, res)

  if(req.headers.host !== '127.0.0.0') return final(403)

  req.pipe(concat(function(data)
  {
    data = JSON.parse(data)

    const port = data.port
    if(!port) return final(422)

    const domain = data.domain
    const externalPort = data.externalPort
    if(domain)
    {
      var entry = domains[domain]
      if(!entry) return res.end()

      if(entry.token !== data.token) return final(422)

      delete domains[domain]
      res.end()
    }
    else if(externalPort)
    {
      var entry = ports[externalPort]
      if(!entry) return res.end()

      if(entry.token !== data.token) return final(422)

      delete ports[externalPort]
      res.end()
    }
    else return final(422)
  }))
}


// Create server to lister for HTTP and WebSockets connections
var server = http.createServer()


// HTTP
server.on('request', function(req, res)
{
  // Inspired by https://github.com/softek/dynamic-reverse-proxy#with-code
  if(req.url === '/_register'  ) return   register(req, res)
  if(req.url === '/_unregister') return unregister(req, res)

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
