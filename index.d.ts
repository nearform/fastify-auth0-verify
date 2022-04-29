import { FastifyPluginCallback, FastifyReply, FastifyRequest } from 'fastify'
import '@fastify/jwt'

import NodeCache from 'node-cache'

export interface FastifyAuth0VerifyOptions {
  /**
   * The Auth0 tenant domain. It enables verification of RS256 encoded tokens.
   * It is also used to verify the token issuer (iss).
   * Either provide a domain or the full URL, including the trailing slash (https://domain.com/).
   */
  readonly domain?: string
  /**
   * The Auth0 audience (aud), usually the API name.
   * If you provide the value true, the domain will be also used as audience.
   * Accepts a string value, or an array of strings for multiple providers.
   */
  readonly audience?: string | readonly string[] | boolean
  /**
   * The Auth0 issuer (iss), usually the API name.
   * By default the domain will be also used as audience.
   * Accepts a string value, or an array of strings for multiple issuers.
   */
  readonly issuer?: string
  /**
   * The Auth0 client secret. It enables verification of HS256 encoded JWT tokens.
   */
  readonly secret?: string
  /**
   * If to return also the header and signature of the verified token.
   */
  readonly complete?: boolean
  /**
   * How long (in milliseconds) to cache RS256 secrets before getting them
   * again using well known JWKS URLS. Setting to 0 or less disables the cache.
   */
  readonly secretsTtl?: string | number
}

export interface Auth0Verify extends Pick<FastifyAuth0VerifyOptions, 'domain' | 'audience' | 'secret'> {
  readonly verify: FastifyAuth0VerifyOptions & {
    readonly algorithms: readonly string[]
    readonly audience?: string | readonly string[]
  }
}

export type Authenticate = (request: FastifyRequest, reply: FastifyReply) => Promise<void>

/**
 * Auth0 verification plugin for Fastify, internally uses @fastify/jwt and jsonwebtoken.
 */
export const fastifyAuth0Verify: FastifyPluginCallback<FastifyAuth0VerifyOptions>
export default fastifyAuth0Verify

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: Authenticate
    auth0Verify: Auth0Verify
  }

  interface FastifyRequest {
    auth0Verify: Auth0Verify
    auth0VerifySecretsCache: Pick<NodeCache, 'get' | 'set' | 'close'>
  }
}
