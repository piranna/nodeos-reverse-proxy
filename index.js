'use strict'

const crypto = require('crypto')
const dgram  = require('dgram')
const fs     = require('fs')
const net    = require('net')
const parse  = require('url').parse
const spawn  = require('child_process').spawn

const basicAuth         = require('basic-auth')
const concat            = require('concat-stream')
const createError       = require('http-errors')
const createProxyServer = require('http-proxy').createProxyServer
const finalhandler      = require('finalhandler')
const uuid              = require('uuid').v4


const LOCALHOST = '127.0.0.1'


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

  fs.stat(home, function(error, statsHome)
  {
    if(error) return callback(error)

    // Get user's logon configuration
    var logon = home+'/etc/logon.json'

    fs.stat(logon, function(error, stats)
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


function ReverseProxy(allowUnpriviledgedPorts)
{
  if(!(this instanceof ReverseProxy))
    return new ReverseProxy(allowUnpriviledgedPorts)


  const domains = {}
  const ports   = {}

  setInterval(function()
  {
    for(var domain in domains)
      fs.access('/proc/'+domains[domain].pid, function(error)
      {
        if(!error) return
        if(error.code !== 'ENOENT') throw error

        domains[domain].proxy.close()
        delete domains[domain]
      })

    for(var key in ports)
      fs.access('/proc/'+ports[key].pid, function(error)
      {
        if(!error) return
        if(error.code !== 'ENOENT') throw error

        ports[key].server.close()
        delete ports[key]
      })
  }, 1000)

  function register(req, res)
  {
    const final = finalhandler(req, res)

    req.pipe(concat(function(data)
    {
      data = JSON.parse(data)

      const pid  = data.pid
      const port = data.port
      if(!pid || !port) return final(createError(422))


      // Domain

      const domain = data.domain
      if(domain)
      {
        var entry = domains[domain]
        if(!entry)
          domains[domain] = entry =
          {
            token: uuid(),
            port: port
          }
        else if(entry.token  !== data.token) return final(createError(422))
        else if(entry.domain === domain) return res.end()

        var options =
        {
          target:
          {
            host: LOCALHOST,
            port: port
          }
        }
        const proxy = createProxyServer(options)

        if(entry.proxy) entry.proxy.close()
        entry.proxy = proxy
        entry.domain = domain

        return res.end(entry.token)
      }


      // Port

      const externalPort = data.externalPort
      if(externalPort)
      {
        // Don't register unpriviledged ports since they can be used directly
        if(!allowUnpriviledgedPorts && externalPort >= 1024)
        {
          const err = new SyntaxError('Unpriviledged ports are not allowed')
                err.statusCode = 422
          return final(err)
        }

        if(externalPort === port)
        {
          const err = new SyntaxError("External and local ports can't be equal")
                err.statusCode = 422
          return final(err)
        }

        const type = data.type
        if(!type) return final(createError(422))

        const key = type+':'+externalPort
        var entry = ports[key]
        if(!entry)
          ports[key] = entry =
          {
            token: uuid(),
            port: port
          }
        else if(entry.token !== data.token) return final(createError(422))
        else if(entry.externalPort === externalPort) return res.end()

        var server
        switch(type)
        {
          case 'tcp':
            server = net.createServer(function(socket)
            {
              const client = net.connect(port, LOCALHOST)
              .on('close', function()
              {
                socket.end()
              })

              const client_end = function(){client.end()}

              // Probably this is not needed, but doesn't hurts...
              this.on('close', client_end)

              socket.pipe(client).pipe(socket).on('close', client_end)
            })
            .listen(externalPort)
          break

          case 'udp4':
          case 'udp6':
            const options =
            {
              type: type,
              reuseAddr: true
            }

            server = dgram.createSocket(options, function(msg, rinfo)
            {
              const client = dgram.createSocket(type)
              .on('message', function(msg)
              {
                server.send(msg, rinfo.port, rinfo.address)
              })

              // [ToDo] When could we able to close the UDP sockets beside When
              // the server exits?
              this.on('close', client.close.bind(client))

              client.send(msg, port, LOCALHOST)
            })
            .bind(externalPort)
          break

          default: return final(createError(422))
        }

        if(entry.server) entry.server.close()
        entry.server = server
        entry.externalPort = externalPort

        return server.on('listening', res.end.bind(res, entry.token))
      }


      // No domain or port

      const err = new SyntaxError('No `domain` or `externalPort` are set')
            err.statusCode = 422
      final(err)
    }))
  }

  function unregister(req, res)
  {
    const final = finalhandler(req, res)

    req.pipe(concat(function(data)
    {
      data = JSON.parse(data)

      const pid = data.pid
      if(!pid) return final(createError(422))


      // Domain

      const domain = data.domain
      if(domain)
      {
        var entry = domains[domain]
        if(!entry) return res.end()

        if(entry.token !== data.token) return final(createError(422))

        domains[domain].proxy.close()
        delete domains[domain]
        return res.end()
      }


      // Port

      const externalPort = data.externalPort
      if(externalPort)
      {
        const type = data.type
        console.log(data, ports)
        if(!type) return final(createError(422))

        const key = type+':'+externalPort
        var entry = ports[key]
        if(!entry) return res.end()

        if(entry.token !== data.token) return final(createError(422))

        ports[key].server.close()
        delete ports[key]
        return res.end()
      }


      // No domain or port

      final(createError(422))
    }))
  }


  //
  // Public API
  //

  this.onRequest = function(req, res)
  {
    const final = finalhandler(req, res)

    const host = req.headers.host.split(':')[0]

    // Inspired by https://github.com/softek/dynamic-reverse-proxy#with-code
    if(host === LOCALHOST)
    {
      if(req.url === '/_register'  ) return   register(req, res)
      if(req.url === '/_unregister') return unregister(req, res)

      return final(createError(403))
    }

    for(var domain in domains)
      if(domain === host)
        return domains[domain].proxy.web(req, res)

    var auth = getAuth(req)
    if(!auth || !auth.name)
    {
      res.statusCode = 401
      res.setHeader('WWW-Authenticate', 'Basic realm="Welcome to NodeOS!"')

      return res.end()
    }

    getProxy(auth, function(error, proxy)
    {
      if(error) return final(error)

      proxy.web(req, res)
    })
  }

  this.onUpgrade = function(req, socket, head)
  {
    for(var domain in domains)
      if(domain === host)
        return domains[domain].proxy.ws(req, socket, head)

    var end = socket.end.bind(socket)

    var auth = getAuth(req)
    if(!auth || !auth.name) return end()

    getProxy(auth, function(error, proxy)
    {
      if(error) return end(error)

      proxy.ws(req, socket, head)
    })
  }
}


module.exports = ReverseProxy
