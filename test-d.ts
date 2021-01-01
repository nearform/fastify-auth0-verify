import Fastify from 'fastify';
import fastifyAuth0Verify from '.';

const fastify = Fastify()

fastify.register(fastifyAuth0Verify, {
  domain: "<auth0 auth domain>",
  audience: "<auth0 app audience>",
})
fastify.register(fastifyAuth0Verify, {
  domain: '<auth0 auth domain>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})

fastify.register(function(instance, _options, done) {
  instance.get('/verify', {
    handler: function(request, reply) {
      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})
