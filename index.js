'use strict'

const { Unauthorized, InternalServerError } = require('http-errors')
const fastifyPlugin = require('fastify-plugin')
const fastifyJwt = require('fastify-jwt')
const jwt = require('jsonwebtoken')
const got = require('got')
const NodeCache = require('node-cache')

const forbiddenOptions = ['algorithms']

const errorMessages = {
  badHeaderFormat: 'Authorization header should be in format: Bearer [token].',
  expiredToken: 'Expired token.',
  invalidAlgorithm: 'Unsupported token.',
  invalidToken: 'Invalid token.',
  jwksHttpError: 'Unable to get the JWS due to a HTTP error',
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
  let { domain, audience, secret, issuer } = options

  // Do not allow some options to be overidden by original user provided
  for (const key of forbiddenOptions) {
    if (key in options) {
      throw new Error(`Option "${key}" is not supported.`)
    }
  }

  // Prepare verification options
  const verify = Object.assign({}, options, { algorithms: [] })

  if (domain) {
    domain = domain.toString()

    // Normalize the domain in order to get a complete URL for JWKS fetching
    if (!domain.match(/^http(?:s?)/)) {
      domain = new URL(`https://${domain}`).toString()
    } else {
      // adds missing trailing slash if it's not been provided in the config
      domain = new URL(domain).toString()
    }

    verify.algorithms.push('RS256')
    verify.issuer = issuer || domain

    if (audience) {
      verify.audience = domain
    }
  }

  if (audience) {
    verify.audience = audience === true ? domain : audience
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

async function getRemoteSecret(domain, alg, kid, cache) {
  try {
    const cacheKey = `${alg}:${kid}:${domain}`

    const cached = cache.get(cacheKey)

    if (cached) {
      return cached
    } else if (cached === null) {
      // null is returned when a previous attempt resulted in the key missing in the JWKs - Do not attemp to fetch again
      throw new Error(errorMessages.missingKey)
    }

    // Hit the well-known URL in order to get the key
    const response = await got(`${domain}.well-known/jwks.json`, { responseType: 'json' })

    // Find the key with ID and algorithm matching the JWT token header
    const key = response.body.keys.find(k => k.alg === alg && k.kid === kid)

    if (!key) {
      // Mark the key as missing
      cache.set(cacheKey, null)
      throw new Error(errorMessages.missingKey)
    }

    // certToPEM extracted from https://github.com/auth0/node-jwks-rsa/blob/master/src/utils.js
    const secret = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----\n`

    // Save the key in the cache
    cache.set(cacheKey, secret)
    return secret
  } catch (e) {
    if (e.response) {
      throw InternalServerError(
        `${errorMessages.jwksHttpError}: [HTTP ${e.response.statusCode}] ${JSON.stringify(e.response.body)}`
      )
    }

    e.statusCode = 500
    throw e
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
    return cb(null, request.auth0Verify.secret)
  }

  // If the algorithm is RS256, get the key remotely using a well-known URL containing a JWK set
  getRemoteSecret(request.auth0Verify.domain, header.alg, header.kid, request.auth0VerifySecretsCache)
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
    // Check if secrets cache is wanted - Convert milliseconds to seconds and cache for a week by default
    const ttl = parseFloat('secretsTtl' in options ? options.secretsTtl : '604800000', 10) / 1e3
    delete options.secretsTtl

    const auth0Options = verifyOptions(options)

    // Setup Fastify-JWT
    instance.register(fastifyJwt, { verify: auth0Options.verify, secret: getSecret })

    // Setup our decorators
    instance.decorate('authenticate', authenticate)
    instance.decorate('auth0Verify', auth0Options)
    instance.decorateRequest('auth0Verify', auth0Options)
    instance.decorateRequest('jwtDecode', jwtDecode)

    // Create a cache or a fake cache
    instance.decorateRequest(
      'auth0VerifySecretsCache',
      ttl > 0 ? new NodeCache({ stdTTL: ttl }) : { get: () => undefined, set: () => false }
    )

    done()
  } catch (e) {
    done(e)
  }
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '3.x' })
