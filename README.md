# fastify-auth0-verify

[![Package Version](https://img.shields.io/npm/v/fastify-auth0-verify.svg)](https://npm.im/fastify-auth0-verify)
[![ci](https://github.com/nearform/fastify-auth0-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/nearform/fastify-auth0-verify/actions/workflows/ci.yml)

Auth0 verification plugin for Fastify, internally uses [@fastify/jwt](https://www.npmjs.com/package/@fastify/jwt).

## Installation

Just run:

```bash
npm install fastify-auth0-verify --save
```

## Usage

Register as a plugin, providing one or more of the following options:

- `jwksUrl`: JSON Web Key Set url (JWKS). The public endpoint returning the set of keys that contain amongst other things the keys needed to verify JSON Web Tokens (JWT). Eg. https://domain.com/.well-known/jwks.json
- `audience`: The intended consumer of the token. This is typically a set of endpoints at which the token can be used. If you provide the value `true`, the domain will be also used as audience. Accepts a string value, or an array of strings for multiple audiences.
- `issuer`: The domain of the system which is issuing OAuth access tokens. By default the domain will be also used as audience. Accepts a string value, or an array of strings for multiple issuers.
- `secret`: The OAuth client secret. It enables verification of HS256 encoded JWT tokens.
- `complete`: If to return also the header and signature of the verified token.
- `secretsTtl`: How long (in milliseconds) to cache RS256 secrets before getting them again using well known JWKS URLS. Setting to 0 or less disables the cache.
- `cookie`: Used to indicate that the token can be passed using cookie, instead of the Authorization header.
  - `cookieName`: The name of the cookie.
  - `signed`: Indicates whether the cookie is signed or not. If set to `true`, the JWT will be verified using the unsigned value.

Since this plugin is based on the [@fastify/jwt](https://www.npmjs.com/package/@fastify/jwt) `verify`, it is also possibile to pass the options documented [here](https://github.com/fastify/fastify-jwt#verify), see the example below.

Once registered, your fastify instance and request will be decorated as describe by `@fastify/jwt`.

In addition, the request will also get the `authenticate` decorator.

This decorator can be used as `preValidation` hook to add authenticate to your routes. The token information will be available in `request.user`.

Example:

```js
const fastify = require('fastify')
const server = fastify()

await server.register(require('fastify-auth0-verify'), {
  jwksUrl: '<JWKS url>',
  audience: '<app audience>'
})

server.get('/verify', { preValidation: server.authenticate }, (request, reply) => {
  reply.send(request.user)
})

server.listen(0, err => {
  if (err) {
    throw err
  }
})
```

You can configure there to be more than one Auth0 API audiences:

```js
await server.register(require('fastify-auth0-verify'), {
  jwksUrl: '<JWKS url>',
  audience: ['<app audience>', '<admin audience>']
})
```

You can include [@fastify/jwt verify](https://github.com/fastify/fastify-jwt#verify) options:

```js
await server.register(require('fastify-auth0-verify'), {
  jwksUrl: '<JWKS url>',
  audience: ['<app audience>', '<admin audience>'],
  cache: true, // @fastify/jwt cache
  cacheTTL: 100, // @fastify/jwt cache ttl
  errorCacheTTL: -1 // @fastify/jwt error cache ttl
})
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Developer notes

### Tests

Tests are currently split into **unit** and **integration**. Integration tests needs the following environment variables:

| Env var               |                                                             |
| --------------------- | ----------------------------------------------------------- |
| `AUTH0_DOMAIN`        | Auth0 dashboard -> application -> Settings -> Domain        |
| `AUTH0_CLIENT_ID`     | Auth0 dashboard -> application -> Settings -> Client ID     |
| `AUTH0_CLIENT_SECRET` | Auth0 dashboard -> application -> Settings -> Client Secret |
| `AUTH0_API_AUDIENCE`  | Auth0 application identifier                                |

## License

Copyright NearForm Ltd. Licensed under the [Apache-2.0 license](http://www.apache.org/licenses/LICENSE-2.0).
