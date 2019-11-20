# fastify-auth0-verify

[![Package Version](https://img.shields.io/npm/v/fastify-auth0-verify.svg)](https://npm.im/fastify-auth0-verify)
[![Dependency Status](https://img.shields.io/david/nearform/fastify-auth0-verify)](https://david-dm.org/nearform/fastify-auth0-verify)
[![Build](https://github.com/nearform/fastify-auth0-verify/workflows/CI/badge.svg)](https://github.com/nearform/fastify-auth0-verify/actions?query=workflow%3ACI)

<!-- [![Code Coverage](https://img.shields.io/codecov/c/gh/nearform/-verify?token=d0ae1643f35c4c4f9714a357f796d05d)](https://codecov.io/gh/nearform/fastify-auth0-verify) -->

Auth0 verification plugin for Fastify, internally uses [fastify-jwt](https://npm.im/fastify-jwt) and [jsonwebtoken](https://npm.im/jsonwebtoken).

## Installation

Just run:

```bash
npm install fastify-auth0-verify --save
```

## Usage

Register as a plugin, providing one or more of the following options:

- `domain`: The Auth0 tenant domain. It enables verification of RS256 encoded JWT tokens. It is also used to verify the token issuer (`iss`). Either provide a domain or the full URL, including the trailing slash (`https://domain.com/`).
- `audience`: The Auth0 audience (`aud`), usually the API name. If you provide the value `true`, the domain will be also used as audience.
- `secret`: The Auth0 client secret. It enables verification of HS256 encoded JWT tokens.
- `complete`: If to return also the header and signature of the verified token.
- `secretsTtl`: How long (in milliseconds) to cache RS256 secrets before getting them again using well known JWKS URLS. Setting to 0 or less disables the cache.

Once registered, your fastify instance and request will be decorated as describe by `fastify-jwt`.

In addition, the request will also get `jwtDecode` and `authenticate` decorators.

The first one is similar to `jwtVerify` but it just performs the JWT token decoding.

The second one can be used as `preValidation` hook to add authenticate to your routes. The token information will be available in `request.user`.

Example:

```js
const server = require('fastify')()

server.register(require('fastify-auth0-verify'), options)

server.register(function(instance, options, done) {
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

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## License

Copyright NearForm Ltd 2019. Licensed under the [Apache-2.0 license](http://www.apache.org/licenses/LICENSE-2.0).
