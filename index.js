'use strict'

const { InternalServerError: Internal, Unauthorized } = require('http-errors')
const fastifyPlugin = require('fastify-plugin')
const fastifyJwt = require('fastify-jwt')
const jwt = require('jsonwebtoken')
const fetch = require('node-fetch')

const errorMessages = {
  badHeaderFormat: 'Authorization header should be in format: Bearer [token].',
  expiredToken: 'Expired token.',
  invalidAlgorithm: 'Unsupported token.',
  invalidToken: 'Invalid token.',
  jwks: 'Unable to get the JWS',
  missingHeader: 'Missing Authorization HTTP header.',
  missingKey: 'No matching key found in the set.',
  missingOptions: 'Please provide at least one of the "domain" or "secret" options.'
}

const fastifyJwtErrors = [
  ['Format is Authorization: Bearer \\[token\\]', errorMessages.badHeaderFormat],
  ['No Authorization was found in request\\.headers', errorMessages.missingHeader],
  ['token expired', errorMessages.expiredToken],
  ['invalid algorithm', errorMessages.invalidAlgorithm],
  [/(?:jwt malformed)|(?:invalid signature)|(?:jwt (?:audience|issuer) invalid)/, errorMessages.invalidToken]
]

function verifyOptions(options) {
  let { domain, audience, secret } = options

  // Do not allow some options to be overidden by original user provided
  delete options.algorithms
  delete options.secret
  delete options.domain
  delete options.audience

  // Prepare verification options
  const verify = Object.assign({ algorithms: [] }, options)

  if (domain) {
    domain = domain.toString()

    // Normalize the domain in order to get a complete URL for JWKS fetching
    if (!domain.match(/^http(?:s?)/)) {
      domain = new URL(`https://${domain}`).toString()
    }

    verify.algorithms.push('RS256')
    verify.issuer = domain

    if (audience) {
      verify.audience = domain
    }
  }

  if (audience) {
    verify.audience = audience === true ? domain : audience.toString()
  }

  if (secret) {
    secret = secret.toString()

    verify.algorithms.push('HS256')
  }

  if (!domain && !secret) {
    // If there is no domain and no secret no verifications are possible, throw an error
    throw new Error(errorMessages.missingOptions)
  }

  return { domain, audience, secret, verify }
}

async function getRemoteSecret(domain, alg, kid) {
  try {
    // Hit the well-known URL in order to get the key
    const response = await fetch(`${domain}.well-known/jwks.json`)

    if (response.status !== 200) {
      throw new Error(`[HTTP ${response.status}] ${await response.text()}`)
    }

    const body = await response.json()

    // Find the key with ID and algorithm matching the JWT token header
    const key = body.keys.find(k => k.alg === alg && k.kid === kid)

    if (!key) {
      throw new Error(errorMessages.missingKey)
    }

    // certToPEM extracted from https://github.com/auth0/node-jwks-rsa/blob/master/src/utils.js
    return `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----\n`
  } catch (e) {
    throw new Internal(`${errorMessages.jwks}: ${e.message}`)
  }
}

function getSecret(request, reply, cb) {
  const decoded = request.jwtDecode({ complete: true })

  // The token is invalid, fastify-jwt will take care of it. For now return a empty key
  if (!decoded) {
    cb(null, '')
  }

  const { header } = decoded

  // If the algorithm is not using RS256, the encryption key is Auth0 client secret
  if (header.alg.startsWith('HS')) {
    return cb(null, request.auth0.secret)
  }

  // If the algorithm is RS256, get the key remotely using a well-known URL containing a JWK set
  getRemoteSecret(request.auth0.domain, header.alg, header.kid)
    .then(key => cb(null, key))
    .catch(cb)
}

function jwtDecode(options = {}) {
  if (!this.headers || !this.headers.authorization) {
    throw new Unauthorized(errorMessages.missingHeader)
  }

  const authorization = this.headers.authorization

  if (!authorization.match(/^Bearer\s+/)) {
    throw new Unauthorized(errorMessages.badHeaderFormat)
  }

  return jwt.decode(authorization.split(/\s+/)[1].trim(), options)
}

async function authenticate(request, reply) {
  try {
    await request.jwtVerify()
  } catch (e) {
    for (const [jwtMessage, errorMessage] of fastifyJwtErrors) {
      if (e.message.match(jwtMessage)) {
        throw new Unauthorized(errorMessage, { a: 1 })
      }
    }

    if (e.statusCode) {
      throw e
    }

    throw new Unauthorized(e.message)
  }
}

function fastifyAuth0Verify(instance, options, done) {
  try {
    const auth0Options = verifyOptions(options)

    // Setup Fastify-JWT
    instance.register(fastifyJwt, { verify: auth0Options.verify, secret: getSecret })

    // Setup our decorators
    instance.decorate('authenticate', authenticate)
    instance.decorate('auth0', auth0Options)
    instance.decorateRequest('auth0', auth0Options)
    instance.decorateRequest('jwtDecode', jwtDecode)

    done()
  } catch (e) {
    done(e)
  }
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '2.x' })
