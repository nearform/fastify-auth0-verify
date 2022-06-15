'use strict'

const { Unauthorized, InternalServerError } = require('http-errors')
const fastifyPlugin = require('fastify-plugin')
const fastifyJwt = require('@fastify/jwt')
const fetch = require('node-fetch')
const NodeCache = require('node-cache')

const forbiddenOptions = ['algorithms']

const errorMessages = {
  badHeaderFormat: 'Authorization header should be in format: Bearer [token].',
  expiredToken: 'Expired token.',
  invalidAlgorithm: 'Unsupported token.',
  invalidToken: 'Invalid token.',
  jwksHttpError: 'Unable to get the JWS due to a HTTP error',
  missingHeader: 'Missing Authorization HTTP header.',
  missingKey: 'Missing Key: Public key must be provided',
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
    verify.allowedIss = issuer || domain

    if (audience) {
      verify.allowedAud = domain
    }
  }

  if (audience) {
    verify.allowedAud = audience === true ? domain : audience
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
      throw new Unauthorized(errorMessages.missingKey)
    }

    // Hit the well-known URL in order to get the key
    const response = await fetch(`${domain}.well-known/jwks.json`, { timeout: 5000 })

    const body = await response.json()

    if (!response.ok) {
      const error = new Error(response.statusText)
      error.response = response
      error.body = body

      throw error
    }

    // Find the key with ID and algorithm matching the JWT token header
    const key = body.keys.find(k => k.alg === alg && k.kid === kid)

    if (!key) {
      // Mark the key as missing
      cache.set(cacheKey, null)
      throw new Unauthorized(errorMessages.missingKey)
    }

    // certToPEM extracted from https://github.com/auth0/node-jwks-rsa/blob/master/src/utils.js
    const secret = `-----BEGIN CERTIFICATE-----\n${key.x5c[0]}\n-----END CERTIFICATE-----\n`

    // Save the key in the cache
    cache.set(cacheKey, secret)
    return secret
  } catch (e) {
    if (e.response) {
      throw InternalServerError(`${errorMessages.jwksHttpError}: [HTTP ${e.response.status}] ${JSON.stringify(e.body)}`)
    }

    e.statusCode = e.statusCode || 500
    throw e
  }
}

function getSecret(request, reply, cb) {
  request
    .jwtDecode({ decode: { complete: true } })
    .then(decoded => {
      const { header } = decoded

      // If the algorithm is not using RS256, the encryption key is Auth0 client secret
      if (header.alg.startsWith('HS')) {
        return cb(null, request.auth0Verify.secret)
      }

      // If the algorithm is RS256, get the key remotely using a well-known URL containing a JWK set
      getRemoteSecret(request.auth0Verify.domain, header.alg, header.kid, request.auth0VerifySecretsCache)
        .then(key => cb(null, key))
        .catch(cb)
    })
    .catch(cb)
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

    // Setup @fastify/jwt
    instance.register(fastifyJwt, {
      verify: auth0Options.verify,
      cookie: options.cookie,
      secret: getSecret,
      jwtDecode: 'jwtDecode'
    })

    // Setup our decorators
    instance.decorate('authenticate', authenticate)
    instance.decorate('auth0Verify', auth0Options)
    instance.decorateRequest('auth0Verify', {
      getter: () => auth0Options
    })

    const cache =
      ttl > 0 ? new NodeCache({ stdTTL: ttl }) : { get: () => undefined, set: () => false, close: () => undefined }

    // Create a cache or a fake cache
    instance.decorateRequest('auth0VerifySecretsCache', {
      getter: () => cache
    })

    instance.addHook('onClose', () => cache.close())

    done()
  } catch (e) {
    done(e)
  }
}

module.exports = fastifyPlugin(fastifyAuth0Verify, { name: 'fastify-auth0-verify', fastify: '4.x' })
