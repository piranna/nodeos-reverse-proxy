'use strict'

const assert       = require('assert')
const createServer = require('http').createServer

const request = require('supertest')

const reverseProxy = require('.')


describe('registration', function()
{
  it('422 when nor `domain` or `externalPort` are set', function(done)
  {
    const fixture =
    {
      pid: process.pid,
      port: 1234
    }

    request(reverseProxy.onRequest)
      .post('/_register')
      .send(fixture)
      .expect(422, function(err, res)
      {
        if(err) return done(err)

        assert.notStrictEqual(res.text, '')

        done()
      })
  })

  describe('domains', function()
  {
    it('register a domain, proxy a request and unregister it', function(done)
    {
      const domain   = 'example.com'
      const expected = 'asdf'

      createServer(function(req, res)
      {
        assert.strictEqual(req.headers.host.split(':')[0], domain)

        res.end(expected)
      })
      .listen(function()
      {
        const port = this.address().port

        const fixture =
        {
          domain: domain,
          pid: process.pid,
          port: port
        }

        const onRequest = request(reverseProxy.onRequest)

        onRequest
        .post('/_register')
        .send(fixture)
        .expect(200, function(err, res)
        {
          if(err) return done(err)

          const token = res.text

          assert.notStrictEqual(token, '')

          onRequest
          .get('/')
          .set('host', domain)
          .expect(200, expected, function(err, res)
          {
            if(err) return done(err)

            const fixture =
            {
              domain: domain,
              pid: process.pid,
              token: token
            }

            onRequest
            .post('/_unregister')
            .send(fixture)
            .expect(200, '', done)
          })
        })
      })
    })
  })

  describe('ports', function()
  {
    it('422 when registering an unpriviledged port', function(done)
    {
      const fixture =
      {
        externalPort: 1234,
        pid: process.pid,
        port: 5678
      }

      request(reverseProxy.onRequest)
      .post('/_register')
      .send(fixture)
      .expect(422, done)
    })

    xit('register a TCP port, proxy a request and unregister it', function(done)
    {
      const fixture =
      {
        externalPort: 1234,
        pid: process.pid,
        port: 1234,
        type: 'tcp'
      }

      request(reverseProxy.onRequest)
      .post('/_register')
      .send(fixture)
      .expect(200, function(err, res)
      {
        if(err) return done(err)

        assert.notStrictEqual(res.text, '')

        done()
      })
    })
  })
})
