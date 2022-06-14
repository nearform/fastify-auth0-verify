/* global describe, beforeEach, afterEach, beforeAll, afterAll, it, expect, jest */

'use strict'

const { readFileSync } = require('fs')
const path = require('path')
const fastify = require('fastify')
const { createSigner } = require('fast-jwt')
const nock = require('nock')

/* eslint-disable max-len */

/*
How to regenerate the keys for RS256:

ssh-keygen -t rsa -b 4096 -m PEM -f private.key
openssl req -x509 -new -key private.key -out public.key -subj "/CN=unused"
*/

const jwks = {
  keys: [
    {
      alg: 'RS512',
      kid: 'KEY',
      x5c: ['UNUSED']
    },
    {
      alg: 'RS256',
      kid: 'KEY',
      x5c: [
        `MIIFAzCCAuugAwIBAgIUYqKCXKygI2fvcK43voYleb27xYgwDQYJKoZIhvcNAQEL
        BQAwETEPMA0GA1UEAwwGdW51c2VkMB4XDTIxMTIwNjA4NDIxOFoXDTIyMDEwNTA4
        NDIxOFowETEPMA0GA1UEAwwGdW51c2VkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
        MIICCgKCAgEA4xLWpT1v6ZiQNp+seqlCBZCZESEt7HVWt+D5rxcQfqOKy0OUvONn
        83N8Q2SybuJ7StD+S3pIm3SWqZXV6N369iJLM+DIyDa4/81NGNdsm6z9X9KTr44v
        uVvljw4h8CbXUSPFdt4uvn0E+RybXfqsPNgFY21KeQZEruIJl/q3V3TvpdvpbFhg
        0+7+piPwTS/oODP1ocY+oMutavrqdL0BWfwKSw/IVMH0PzhSyd28Yn5e98XHw7og
        oDZgF5RYaNKKK/L5waU7KYI8bQwZ72v+qBhBKiC68ZaA9wGZlvNw08/IdE6zP5AY
        4Mpcpd0BK7NC+R6HXlqcqp+Fgrn/3c/+nyPcNTH/O40LOLlxGG1d66utUPl5oatY
        XIcH55GHrrXw5l31tQPxMT44B8FFtv2VAxYuXPzIbnMOlYJK4yu9n0j3PpN/rDWD
        Ki7k9bLCNB26NOuwqdUrcpIBtbv/pqgFnOgbZVQfudsT9sGeNP5m6luT6KM/bZ3Z
        ljyL1t1Skrtlym6LPAg7cNtfzN2wQfZGhOWraYT/qgkZbNsfaNxaLscrdxHwlvi/
        5ObBGMNK33Dz1uY4rlan/fD/6wSUBKel7UlPq636/WTR/FYlttshp3RVD0nlAZEm
        BYP5VfOfWsiXxYbVEnHyBUX6sS8RAtMwX3/qAbc6+2e/ymnRhyfZDcECAwEAAaNT
        MFEwHQYDVR0OBBYEFMHvQkKUefNH3fepeNVVbGcWQAGlMB8GA1UdIwQYMBaAFMHv
        QkKUefNH3fepeNVVbGcWQAGlMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
        BQADggIBAFbN5uDPyWg4vttGpihOrYszC5o172TOw/Tmp4ggtltLexJKSXd5UKVP
        MD2oXJB1WW6YTae5hZSBcXUJ+Gmu54V7Ge2Lcv19zQkKu5OhJD0cn6L51s8iMdzP
        5yvZRgM00+Pdzizl/NkZgSE/b6W9zEE4ZmhPa8aLKjKxQlv42HAUyFAqHiiPzOpq
        +vDZPTz4lxnERfXnF4eVSMmkyB2f0T3ilIg+Mjwbe2m749FanVCse3E5cgPJVFYl
        h2bs5/pb7rVfkRNt89IW7icZZGkqHn88y0EksjawF4O2eX5mCgEBM7/TCAWR84qW
        OOhZzwxJh68NlzRfuvNqTLQrVdP0xQNFY3b7gWDRf6vqc7KGJr2cwqDsKXFQqqp0
        IgA9Tfd8FNIgTnsR+RvybYQHcg60Vd4HlzxWqVs/d7baZLUIi4alFkBFQyuV0jAt
        jXg+kbow83jsg57ZcIxdFD/2RZj34TCTvsoDuhZEgqgHZs07HfNbDRcQ195A8D3t
        ax0dsIii8tCkffEyzRwmFgcGHBh+2CvH0/p5Sn8RdBqamjNgko7QqrYNMRMP3I71
        lXoKOhH7jk9Nis2d2i+ktNy0IMQdWsV75FP+yE3CWTl10bMvCvccg0B1dVmxAbDZ
        h7b8BjRiGIgwqVjdclzAy0sVMZHquiFvoiE78n5rndcI9jtzx0Ub`.trim()
      ]
    }
  ]
}

const generateToken = (options, payload) => {
  const signSync = createSigner(options)
  return signSync(payload)
}

const tokens = {
  hs256Valid: generateToken(
    { key: 'secret', noTimestamp: true },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  hs256ValidWithIssuer: generateToken(
    { key: 'secret', noTimestamp: true, iss: 'https://localhost/' },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  hs256ValidWithProvidedIssuer: generateToken(
    { key: 'secret', noTimestamp: true, iss: 'foo' },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  hs256ValidWithAudience: generateToken(
    { key: 'secret', noTimestamp: true, aud: 'foo' },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  hs256ValidWithDomainAsAudience: generateToken(
    { key: 'secret', noTimestamp: true, aud: 'https://localhost/', iss: 'https://localhost/' },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  hs256InvalidSignature:
    generateToken(
      { key: 'secret', noTimestamp: true },
      {
        admin: true,
        name: 'John Doe',
        sub: '1234567890'
      }
    ) + '-INVALID',

  rs256Valid: generateToken(
    {
      key: readFileSync(`${path.join(__dirname, 'keys')}/private.key`, 'utf8'),
      noTimestamp: true,
      iss: 'https://localhost/',
      kid: 'KEY'
    },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  rs256ValidWithAudience: generateToken(
    {
      key: readFileSync(`${path.join(__dirname, 'keys')}/private.key`, 'utf8'),
      noTimestamp: true,
      iss: 'https://localhost/',
      aud: 'foo',
      kid: 'KEY'
    },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  rs256ValidWithDomainAsAudience: generateToken(
    {
      key: readFileSync(`${path.join(__dirname, 'keys')}/private.key`, 'utf8'),
      noTimestamp: true,
      iss: 'https://localhost/',
      aud: 'https://localhost/',
      kid: 'KEY'
    },
    {
      admin: true,
      name: 'John Doe',
      sub: '1234567890'
    }
  ),
  rs256InvalidSignature:
    generateToken(
      {
        key: readFileSync(`${path.join(__dirname, 'keys')}/private.key`, 'utf8'),
        noTimestamp: true,
        iss: 'https://localhost/',
        kid: 'KEY'
      },
      {
        admin: true,
        name: 'John Doe',
        sub: '1234567890'
      }
    ) + '-INVALID',
  rs256MissingKey:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFOT1RIRVItS0VZIn0.eyJwYXlsb2FkIjp7InN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIn19.jZrn8F1RClAbb4P1JJR0XJ0KTw0U7DqQEd098AQhxjojb-6BfGwxABn-hIrFeQhDPs1-RtzCfoRJ0WvA40UoqAPf071gdlB5FFq95lUO_9B8XXby0ueUe-RdlqMkP3HvukLLFhQW481zBEVAyp8xSz-P1LsYHk6avCA1lAGMKZoh6FOsoE-cyBMKF0koc2MWUPvu6BYr48gyX50QKBr_yrSdfLgQj67tcMicvESddwZX1ggr7eF4ZeHXVZV_F_AMkOywiEkiS4EvC2gywNJkbIz3eLqsQFYYzUhMsQfu5x-YfSw3-pmEtw7SQZ-QeP2zs1sZP0tcJJ03ya-dcG1E7IindR1eAoji6CYtRElF0DMsIgV-Cd6NB1Vx5R-Le15MROuvArGisJKOlHYf79g1-1hWC5LAtQ0eAR5gkeRRX6UjUL_kCMVtf69qed74mq-nA4P2BNW72CL9SzjPwmNeUVfGdui10NLMt9QAs8jcYksgeMiMoQW6NVvsc9ptKmynmTJzCEP1s-Jgv0erMIIe5_mU9YnihZHJ19dL7BDvg0YV_tP3i6vRXqJsYBx43YPKMwiI5OKRSregfRLvq66JSlL7k2hfIVRLhJc-tvaxoeewDJc1qksc-qgsBWwQ7lVpQlj_mBbmzujXmj99nQJfqpV9iPS5WPPCbtJTeTlXcP8',

  unsupportedAlgorithm:
    'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.nZU_gPcMXkWpkCUpJceSxS7lSickF0tTImHhAR949Z-Nt69LgW8G6lid-mqd9B579tYM8C4FN2jdhR2VRMsjtA',
  expired:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTQxNjIzOTAyMiwiZXhwIjoxNTExMjM5MDIyfQ.zTxEk-Z5qfP4n7U4jMU1gRvQEpl4HhnYTniTeQpaMkI',
  invalidAudience:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImF1ZCI6ImJhciJ9.Z0NHItgQv74Ce9re2q9qca_ifOn_cgndSaKBENZfN7M',
  invalidIssuer:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6ImJhciJ9.jG2FWFY709fd9ooB4NgU1YpPmT4gp_Ig8JisFZAOBS0'
}
/* eslint-enable max-len */

async function buildServer(options) {
  const server = fastify()

  server.register(require('.'), options)
  server.register(require('@fastify/cookie'))
  server.register(function (instance, options, done) {
    instance.get('/verify', {
      async handler(request) {
        return request.user
      },
      preValidation: instance.authenticate
    })

    instance.get('/decode', {
      async handler(request) {
        return {
          regular: await request.jwtDecode(),
          full: await request.jwtDecode({ decode: { complete: true } })
        }
      }
    })

    done()
  })

  await server.listen(0)

  return server
}

describe('Options parsing', function () {
  it('should enable RS256 when the domain is present', async function () {
    const server = await buildServer({ domain: 'localhost' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['RS256'])

    server.close()
  })

  it('should enable HS256 when the secret is present', async function () {
    const server = await buildServer({ secret: 'secret' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['HS256'])

    server.close()
  })

  it('should enable both algorithms is both options are present', async function () {
    const server = await buildServer({ domain: 'http://localhost', secret: 'secret' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['RS256', 'HS256'])

    server.close()
  })

  it('should complain if neither domain or secret are present', async function () {
    await expect(buildServer()).rejects.toThrow('Please provide at least one of the "domain" or "secret" options.')
  })

  it('should complain if forbidden options are present', async function () {
    await expect(buildServer({ algorithms: 'whatever' })).rejects.toThrow('Option "algorithms" is not supported.')
  })
})

describe('JWT token decoding', function () {
  let server

  beforeAll(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterAll(() => server.close())

  it('should decode a JWT token', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/decode',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      regular: {
        admin: true,
        name: 'John Doe',
        sub: '1234567890'
      },
      full: {
        header: {
          alg: 'HS256',
          typ: 'JWT'
        },
        input:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9',
        payload: {
          admin: true,
          name: 'John Doe',
          sub: '1234567890'
        },
        signature: 'eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk'
      }
    })
  })

  it('should complain if the HTTP Authorization header is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode' })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.headers'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(400)
    expect(response.json()).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Format is Authorization: Bearer [token]'
    })
  })
})

describe('JWT cookie token decoding', function () {
  let server

  beforeAll(async function () {
    server = await buildServer({ secret: 'secret', token: 'token', cookie: { cookieName: 'token' } })
  })

  afterAll(() => server.close())

  it('should decode a JWT token from cookie', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/decode',
      cookies: {
        token: tokens.hs256Valid
      }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      regular: {
        admin: true,
        name: 'John Doe',
        sub: '1234567890'
      },
      full: {
        header: {
          alg: 'HS256',
          typ: 'JWT'
        },
        input:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoiMTIzNDU2Nzg5MCJ9',
        payload: {
          admin: true,
          name: 'John Doe',
          sub: '1234567890'
        },
        signature: 'eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk'
      }
    })
  })

  it('should complain if the JWT token cookie is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', cookies: { foo: 'bar' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.cookies'
    })
  })

  it('should complain if the JWT token cookie is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', cookies: { foo: 'bar' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.cookies'
    })
  })
})

describe('HS256 JWT token validation', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterEach(() => server.close())

  it('should make the token informations available through request.user', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({ sub: '1234567890', name: 'John Doe', admin: true })
  })

  it('should make the complete token informations available through request.user', async function () {
    await server.close()
    server = await buildServer({ secret: 'secret', complete: true })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      header: { alg: 'HS256', typ: 'JWT' },
      payload: { sub: '1234567890', name: 'John Doe', admin: true },
      signature: 'eNK_fimsCW3Q-meOXyc_dnZHubl2D4eZkIcn6llniCk'
    })
  })

  it('should validate the issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/'
    })
  })

  it('should validate provided issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', issuer: 'foo' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithProvidedIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'foo'
    })
  })

  it('should validate multiple issuers', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', issuer: ['bar', 'foo', 'blah'] })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithProvidedIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'foo'
    })
  })

  it('should validate the audience', async function () {
    await server.close()
    server = await buildServer({ audience: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({ sub: '1234567890', name: 'John Doe', admin: true, aud: 'foo' })
  })

  it('should validate the audience using the domain', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: true, secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithDomainAsAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'https://localhost/'
    })
  })

  it('should reject an invalid signature', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256InvalidSignature}` }
    })

    expect(response.statusCode).toEqual(401)

    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The token signature is invalid.'
    })
  })
})

describe('RS256 JWT token validation', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ domain: 'https://localhost/' })
  })

  afterEach(() => server.close())

  beforeEach(function () {
    nock.disableNetConnect()

    nock('https://localhost/').get('/.well-known/jwks.json').reply(200, jwks)
  })

  afterEach(() => {
    nock.cleanAll()
    nock.enableNetConnect()
  })

  it('should make the token informations available through request.user', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/'
    })
  })

  it('should make the complete token informations available through request.user', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', complete: true })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      header: {
        alg: 'RS256',
        kid: 'KEY',
        typ: 'JWT'
      },
      payload: {
        sub: '1234567890',
        name: 'John Doe',
        admin: true,
        iss: 'https://localhost/'
      },
      signature:
        'HYgGxrwl3vthMChCy44eg-VK0x_SR-mf6761VI9jNk9rMqKZmFcabE7dVUA_hCKFXyj7VL7bJ09i3PxYFkj78PMz28B9hZz_h4ntVuafPmDL9FCHvW91oZTJRhosNor2yyUFcx6ijfu6WeUTZRtQdBqvcAgtKutNl9H0Q0wff-Jn10ViiFJTEmiaC-XhoZFjZQee7_bS7mOZtJCZeH69D_CWrCf4I-N2nl8U1sVHp-H0fRCc5D5SvlIhCsIXYJoFDRAuTtRvwrXXVPlIPugCeJ8l91S-GbIEEUejDCE8JPW9bEGfKoAFBiIbnRBSb4hKEbdFUqWHk-5_YOLzvPnq57vlCB8yeC10exEgiSeSb74tXGZyB4z540Mjt-2k9O9t7Uz1ICDZHvrYLUN2wzlSKqSucOvr5YpH8y-iLaWqAQeiR2b6w0u_c9kMEgzCAaobJp4QxjGkKHfYNmUFlV1uoY5_I2CBls-ICr0_E9PicMBnddg_JG8KabqAmZObCrkM5WRxSPPNLTElmw80MACxFqgaKxsMg-6uqmgTwy9ie9TjYVVdL1pdxWWaLDhzpDN1mmdTuIazfnSaib7PnzgPPgHlN7TnSCmCnYzffAg-i2Fz8JOhiK50mF86hc8n6em6K7cbVLm0nQcA4249D88Um9KBs8AoPXov8HGAS4Khwhk' // eslint-disable-line max-len
    })
  })

  it('should validate the audience', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: 'foo' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'foo'
    })
  })

  it('should validate the audience using the domain', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: true, secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithDomainAsAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'https://localhost/'
    })
  })

  it('should validate with multiple audiences ', async function () {
    await server.close()
    server = await buildServer({
      domain: 'localhost',
      audience: ['https://otherhost/', 'foo', 'https://somehost/'],
      secret: 'secret'
    })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'foo'
    })
  })

  it('should reject an invalid signature', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256InvalidSignature}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The token signature is invalid.'
    })
  })

  it('should reject a token when is not possible to retrieve the JWK set due to a HTTP error', async function () {
    nock.cleanAll()

    nock('https://localhost/').get('/.well-known/jwks.json').reply(404, { error: 'Not found.' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(response.json()).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'Unable to get the JWS due to a HTTP error: [HTTP 404] {"error":"Not found."}'
    })
  })

  it("should reject a token when the retrieved JWT set doesn't have the required key", async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
    })
  })

  it('should reject a token when the retrieved JWT set returns an invalid key', async function () {
    nock.cleanAll()

    nock('https://localhost/')
      .get('/.well-known/jwks.json')
      .reply(200, {
        keys: [
          {
            alg: 'RS256',
            kid: 'KEY',
            x5c: ['FOO']
          }
        ]
      })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: Unsupported PEM public key.'
    })
  })

  it('should reject a token when is not possible to retrieve the JWK set due to a generic error', async function () {
    nock.cleanAll()
    nock.enableNetConnect()

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(response.json()).toEqual({
      code: 'ECONNREFUSED',
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'request to https://localhost/.well-known/jwks.json failed, reason: connect ECONNREFUSED 127.0.0.1:443'
    })
  })

  it('should cache the key and not it the well-known URL more than once', async function () {
    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
  })

  it('should correctly get the key again from the well-known URL if cache expired', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', secretsTtl: 10 })

    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    await new Promise(resolve => setTimeout(resolve, 20))

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    const body = response.json()

    expect(response.statusCode).toEqual(500)
    expect(body).toMatchObject({
      statusCode: 500,
      error: 'Internal Server Error'
    })

    expect(body.message).toMatch(/Nock: No match for request/)
  })

  it('should not cache the key if cache was disabled', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', secretsTtl: 0 })

    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    const body = response.json()

    expect(response.statusCode).toEqual(500)
    expect(body).toMatchObject({
      statusCode: 500,
      error: 'Internal Server Error'
    })

    expect(body.message).toMatch(/Nock: No match for request/)
  })

  it('should not try to get the key twice when using caching if a previous attempt failed', async function () {
    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
    })

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
    })
  })
})

describe('General error handling', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterEach(() => server.close())

  it('should complain if the HTTP Authorization header is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify' })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Authorization HTTP header.'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization header should be in format: Bearer [token].'
    })
  })

  it('should complain if the JWT token is malformed', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'Bearer FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'The token is malformed.'
    })
  })

  it('should complain if the JWT token has an unsupported algorithm', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.unsupportedAlgorithm}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'The token algorithm is invalid.'
    })
  })

  it('should complain if the JWT token has expired', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.expired}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Expired token.'
    })
  })

  it('should complain if the JWT token has an invalid issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.invalidIssuer}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The iss claim value is not allowed.'
    })
  })

  it('should complain if the JWT token has an invalid audience', async function () {
    await server.close()
    server = await buildServer({ audience: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.invalidAudience}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The aud claim value is not allowed.'
    })
  })
})

describe('Cleanup', function () {
  it('should close the cache when the server stops', function (done) {
    jest.resetModules()
    expect.assertions(1)

    const mockCache = {
      close: jest.fn()
    }

    jest.doMock(
      'node-cache',
      jest.fn().mockImplementation(
        () =>
          function NodeCache() {
            return mockCache
          }
      )
    )

    buildServer({ secret: 'secret' }).then(server => {
      server.close(() => {
        expect(mockCache.close).toHaveBeenCalled()
        done()
      })
    }, done)
  })
})
