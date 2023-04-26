const Fastify = require('fastify')
const { OAuth2Server } = require('oauth2-mock-server')
const fetch = require('cross-fetch')

async function buildOAuthServer() {
  const server = new OAuth2Server()

  // Generate a new RSA key and add it to the keystore
  await server.issuer.keys.generate('RS256')

  // Start the server
  await server.start(8080, 'localhost')
  return server
}

async function buildServer({ oAuthServerUrl }) {
  const server = Fastify()

  // Setup fastify-auth0-verify
  await server.register(require('../'), {
    jwksUrl: `${oAuthServerUrl}/jwks`,
    issuer: oAuthServerUrl
  })

  // Setup auth0 protected route
  server.get('/protected', { preValidation: server.authenticate }, (req, reply) => {
    reply.send({ route: 'Protected route' })
  })

  // Setup auth0 public route
  server.get('/public', (req, reply) => {
    reply.send({ route: 'Public route' })
  })

  await server.listen({ port: 0 })
  return server
}

describe('Authentication against oauth2 mocked server', () => {
  let server
  let OAuthServer

  beforeAll(async function () {
    OAuthServer = await buildOAuthServer()
    server = await buildServer({ oAuthServerUrl: OAuthServer.issuer.url })
  })

  afterAll(async () => {
    server.close()
    await OAuthServer.stop()
  })

  it('Protects protected routes', async () => {
    const publicResponse = await server.inject('/public')
    expect(publicResponse.statusCode).toEqual(200)
    expect(publicResponse.json()).toEqual({ route: 'Public route' })

    const protectedResponseWithoutAuthHeader = await server.inject('/protected')
    expect(protectedResponseWithoutAuthHeader.statusCode).toEqual(401)
    expect(protectedResponseWithoutAuthHeader.json()).toEqual({
      error: 'Unauthorized',
      message: 'Missing Authorization HTTP header.',
      statusCode: 401
    })

    const invalidAuthToken =
      'Bearer eyuhbGcpOpuSUzI1NpIsInR5cCI6IkpOVCIsImtpZCI6IkNPTFuKTFumQ2tZeURuSE1aamNUap7.eyupc3MpOpuodHRwczovL2Rldp0zZTh1d2poYjF4MnZqY2U4LnVzLmF1dGgwLmNvbS8pLCuzdWIpOpu6RUIzaEM0VUhrV3hjQ3uOQ2d2RzZlNkdmQOuZRkRrYUBjbGllbnRzIpwpYOVkIjopSldULOZlcmlmeS10ZON0IpwpaWF0IjoxNjgxODM0NjYxLCuleHApOjE2ODE5MjEwNjEsImF6cCI6InpFQjNoQzRVSGtOeGNDcldDZ3ZHNmU2R2ZBcllGRGthIpwpZ3R5IjopY2xpZW50LWNyZWRlbnRpYWxzIn0.MdxfrZF5EB9ByFABzEdBGENjc0d9eoML_TDKftxrg2352VqvoD3dnxxn1rpIAqjcpWSI4BKvf3hNlcDwoOyhT2kmHxDgcNv22dG9ZAY5vEkm6csDtUeBbVuqdjx30zwbcYDf_pZ4euuCLE-ysOI8WpvYvsOGTjGBpjdFZAyGqPIL0RTUrtwh6lrVzGGl9oKPQgq-ZuFOtUQOO7w4jItHZ40SpvzPYfrLY4P6DfYbxcwSTc9OjE86vvUON0EunTdjhkyml-c28svnxu5WFvfsuUT56Cbw1AYKogg12-OHLYuyS2VQblxCQfIogaDZPTY114M8PCb0ZBL19jNO6oxzA'
    const protectedResponseWithInvalidAuthHeader = await server.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        Authorization: invalidAuthToken
      }
    })
    expect(protectedResponseWithInvalidAuthHeader.statusCode).toEqual(401)
    expect(protectedResponseWithInvalidAuthHeader.json()).toEqual({
      code: 'FST_JWT_AUTHORIZATION_TOKEN_INVALID',
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The token header is not a valid base64url serialized JSON.',
      statusCode: 401
    })
  })

  it('Returns protected route when expected auth header is provided', async () => {
    if (process.version.startsWith('v14')) {
      console.log('Skipping test on v14')
      return
    }

    const authResponse = await fetch(`${OAuthServer.issuer.url}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials'
      })
    })

    const { token_type: tokenType, access_token: accessToken } = await authResponse.json()
    const protectedResponse = await server.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        Authorization: `${tokenType} ${accessToken}`
      }
    })

    expect(protectedResponse.statusCode).toEqual(200)
    expect(protectedResponse.json()).toEqual({ route: 'Protected route' })
  })
})
