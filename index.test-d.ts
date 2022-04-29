import Fastify from 'fastify'
import fastifyAuth0Verify from '.'
import { expectAssignable, expectType } from 'tsd'
import { DecodePayloadType, FastifyJwtDecodeOptions } from '@fastify/jwt'
import fastifyJWT from '@fastify/jwt'

const fastify = Fastify()

fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})
fastify.register(fastifyJWT, {
  secret: '<jwt secret>',
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      expectAssignable<Function>(request.jwtDecode);

      const options: FastifyJwtDecodeOptions = {
        decode:{
          complete: true
        },
        verify:{}
      }

      expectType<Promise<DecodePayloadType>>(request.jwtDecode(options))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode({decode:{ complete: true }, verify:{}}))
      expectType<Promise<DecodePayloadType>>(request.jwtDecode())

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
