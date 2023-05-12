'use strict'

const fastifyPlugin = require('fastify-plugin')
const fastifyJwtJwks = require('fastify-jwt-jwks').fastifyJwtJwks

function fastifyAuth0Verify(instance, options, done) {
  if (options.domain) {
    const domain = options.domain
    delete options.domain
    options.jwksUrl = `${domain}.well-known/jwks.json`
  }
  return fastifyJwtJwks(instance, options, done)
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '4.x' })
