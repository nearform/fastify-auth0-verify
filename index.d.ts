import { FastifyPluginCallback, FastifyReply, FastifyRequest } from 'fastify'
import { UserType, SignPayloadType } from '@fastify/jwt'

import NodeCache from 'node-cache'

declare module 'fastify' {
  interface FastifyInstance {
    authenticate: fastifyAuth0Verify.Authenticate
    auth0Verify: fastifyAuth0Verify.Auth0Verify
  }

  interface FastifyRequest {
    auth0Verify: fastifyAuth0Verify.Auth0Verify
    auth0VerifySecretsCache: Pick<NodeCache, 'get' | 'set' | 'close'>
  }
}

type FastifyAuth0Verify = FastifyPluginCallback<fastifyAuth0Verify.FastifyAuth0VerifyOptions>

declare namespace fastifyAuth0Verify {
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
     * Accepts a string value, or an array of strings or regexes for multiple
     * issuers.
     */
    readonly issuer?: string | RegExp | (RegExp | string)[]
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

    /**
     * Used to indicate that the token can be passed using cookie, instead of the Authorization header.
     */
    readonly cookie?: {
      /**
       *  The name of the cookie.
       */
      cookieName: string

      /**
       *  Indicates whether the cookie is signed or not. If set to `true`, the JWT
       *  will be verified using the unsigned value.
       */
      signed?: boolean
    }
    /**
     * You may customize the request.user object setting a custom sync function as parameter:
     */
    readonly formatUser?: (payload: SignPayloadType) => UserType
  }

  export type Authenticate = (request: FastifyRequest, reply: FastifyReply) => Promise<void>

  export interface Auth0Verify
    extends Pick<fastifyAuth0Verify.FastifyAuth0VerifyOptions, 'domain' | 'audience' | 'secret'> {
    readonly verify: fastifyAuth0Verify.FastifyAuth0VerifyOptions & {
      readonly algorithms: readonly string[]
      readonly audience?: string | readonly string[]
    }
  }

  export const fastifyAuth0Verify: FastifyAuth0Verify
  export { fastifyAuth0Verify as default }
}

declare function fastifyAuth0Verify(...params: Parameters<FastifyAuth0Verify>): ReturnType<FastifyAuth0Verify>

export = fastifyAuth0Verify
