import Fastify from 'fastify'
import fastifyAuth0Verify from '.'
import { expectAssignable, expectType } from 'tsd'
import { DecodePayloadType, FastifyJwtDecodeOptions } from '@fastify/jwt'
import fastifyJWT from '@fastify/jwt'

const fastify = Fastify()

fastify.register(fastifyAuth0Verify, {
  jwksUrl: '<JWKS url>',
  issuer: '<auth0 issuer>',
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  jwksUrl: '<JWKS url>',
  issuer: /<auth0 issuer>/,
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  jwksUrl: '<JWKS url>',
  issuer: ['<auth0 issuer>', /<auth0 issuer>/],
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})
fastify.register(fastifyAuth0Verify, {
  jwksUrl: '<JWKS url>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})
fastify.register(fastifyJWT, {
  secret: '<jwt secret>'
})
fastify.register(fastifyAuth0Verify, {
  cookie: {
    cookieName: '<cookie>',
    signed: true
  }
})
fastify.register(fastifyAuth0Verify, {
  jwksUrl: '<JWKS url>',
  issuer: '<auth0 issuer>',
  audience: '<auth0 app audience>',
  formatUser: () => ({ foo: 'bar' })
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      expectAssignable<Function>(request.jwtDecode)

      const options: FastifyJwtDecodeOptions = {
        decode: {
          complete: true
        },
        verify: {}
      }

      expectType<Promise<DecodePayloadType>>(request.jwtDecode(options))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode({ decode: { complete: true }, verify: {} }))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode())

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
