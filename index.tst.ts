import { expect } from 'tstyche'
import Fastify from 'fastify'
import fastifyAuth0Verify from '.'
import { DecodePayloadType, FastifyJwtDecodeOptions } from '@fastify/jwt'
import fastifyJWT from '@fastify/jwt'

const fastify = Fastify()

fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  issuer: '<auth0 issuer>',
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  issuer: /<auth0 issuer>/,
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  issuer: ['<auth0 issuer>', /<auth0 issuer>/],
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
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
  domain: '<auth0 auth domain>',
  issuer: '<auth0 issuer>',
  audience: '<auth0 app audience>',
  formatUser: () => ({ foo: 'bar' }),
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      expect(request.jwtDecode).type.toBeAssignableTo<Function>()

      const options: FastifyJwtDecodeOptions = {
        decode:{
          complete: true
        },
        verify:{}
      }

      expect(request.jwtDecode(options)).type.toBe<Promise<DecodePayloadType>>()
      expect(request.jwtDecode({decode:{ complete: true }, verify:{}})).type.toBe<Promise<DecodePayloadType>>()
      expect(request.jwtDecode()).type.toBe<Promise<DecodePayloadType>>()

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
