import Fastify from 'fastify'
import fastifyAuth0Verify from '.'
import { expectAssignable, expectType } from 'tsd'
import { DecodeOptions, JwtPayload, Jwt } from 'jsonwebtoken'

const fastify = Fastify()

fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: '<auth0 app audience>'
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})

fastify.register(function (instance, _options, done) {
  instance.get('/verify', {
    handler: function (request, reply) {
      expectAssignable<Function>(request.jwtDecode)

      const options: DecodeOptions = {
        complete: true,
        json: true
      }

      expectType<null | JwtPayload | Jwt>(request.jwtDecode(options))
      expectType<null | JwtPayload | Jwt>(request.jwtDecode({ json: true }))
      expectType<null | JwtPayload | Jwt>(request.jwtDecode({ complete: true }))
      expectType<null | JwtPayload | Jwt>(request.jwtDecode())

      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
