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

- `domain`: The Auth0 tenant domain. It enables verification of RS256 encoded JWT tokens. It is also used to verify the token issuer (`iss`). Either provide a domain or the full URL, including the trailing slash (`https://domain.com/`).
- `audience`: The Auth0 audience (`aud`), usually the API name. If you provide the value `true`, the domain will be also used as audience. Accepts a string value, or an array of strings for multiple providers. 
- `issuer`: The Auth0 issuer (`iss`), usually the API name. By default the domain will be also used as audience. Accepts a string value, or an array of strings for multiple issuers. 
- `secret`: The Auth0 client secret. It enables verification of HS256 encoded JWT tokens.
- `complete`: If to return also the header and signature of the verified token.
- `secretsTtl`: How long (in milliseconds) to cache RS256 secrets before getting them again using well known JWKS URLS. Setting to 0 or less disables the cache.
- `cookie`: Used to indicate that the token can be passed using cookie, instead of the Authorization header.
  - `cookieName`: The name of the cookie.

Once registered, your fastify instance and request will be decorated as describe by `@fastify/jwt`.

In addition, the request will also get the `authenticate` decorator.

This decorator can be used as `preValidation` hook to add authenticate to your routes. The token information will be available in `request.user`.

Example:

```js
const server = require('fastify')()

server.register(require('fastify-auth0-verify'), {
  domain: "<auth0 auth domain>",
  audience: "<auth0 app audience>",
})

server.register(function(instance, _options, done) {
  instance.get('/verify', {
    handler: function(request, reply) {
      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })

  done()
})

server.listen(0, err => {
  if (err) {
    throw err
  }
})
```

You can configure there to be more than one Auth0 API audiences: 

```js
const server = require('fastify')()

server.register(require('fastify-auth0-verify'), {
  domain: '<auth0 auth domain>',
  audience: ['<auth0 app audience>', '<auth0 admin audience>']
})

server.register(function(instance, _options, done) {
  instance.get('/verify', {
    handler: function(request, reply) {
      reply.send(request.user)
    },
    preValidation: instance.authenticate
  })
  done()
})

server.listen(APP_PORT, err => {
  if (err) {
    throw err
  }
})
```

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## License

Copyright NearForm Ltd. Licensed under the [Apache-2.0 license](http://www.apache.org/licenses/LICENSE-2.0).
