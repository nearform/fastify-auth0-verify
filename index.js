'use strict'

const fastifyPlugin = require('fastify-plugin')
const fastifyJwtJwks = require('fastify-jwt-jwks').fastifyJwtJwks

const errorMessages = {
  missingOptions: 'Please provide at least one of the "domain" or "secret" options.'
}

function fastifyAuth0Verify(instance, options, done) {
  try {
    let { domain, secret } = options

    if (domain) {
      delete options.domain

      domain = domain.toString()

      if (!domain.match(/^http(?:s?)/)) {
        domain = new URL(`https://${domain}`).toString()
      } else {
        // Add missing trailing slash if it hasn't been provided in the config
        domain = new URL(domain).toString()
      }

      options.jwksUrl = `${domain}.well-known/jwks.json`
    } else if (!secret) {
      // Throw missing options error here to prevent confusing error 
      // message from fastify-jwt-jwks being thrown to user
      throw new Error(errorMessages.missingOptions)
    }

    return fastifyJwtJwks(instance, options, done)
  } catch (e) {
    done(e)
  }
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '4.x' })
