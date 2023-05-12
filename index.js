'use strict'

const fastifyPlugin = require('fastify-plugin')
const fastifyJwtJwks = require('fastify-jwt-jwks').fastifyJwtJwks

const errorMessages = {
  missingOptions: 'Please provide at least one of the "domain" or "secret" options.'
}

function fastifyAuth0Verify(instance, options, done) {
  const { domain, secret } = options

  if (!domain && !secret) {
    // Domain or secret are required for verification
    // Checking for secret here prevents a misleading error message if neither
    // jwksUrl or secret are passed to fastify-jwt-jwks
    throw new Error(errorMessages.missingOptions)
  }

  if (domain) {
    delete options.domain
    options.jwksUrl = `${domain}.well-known/jwks.json`
  }

  return fastifyJwtJwks(instance, options, done)
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '4.x' })
