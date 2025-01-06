# fastify-auth0-verify

[![Package Version](https://img.shields.io/npm/v/fastify-auth0-verify.svg)](https://npm.im/fastify-auth0-verify)
[![ci](https://github.com/nearform/fastify-auth0-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/nearform/fastify-auth0-verify/actions/workflows/ci.yml)

Auth0 verification plugin for Fastify. 

Internally this is a lighweight wrapper around [fastify-jwt-jwks](https://github.com/nearform/fastify-jwt-jwks) and accepts most of the same options. The differences are highlighted in this document. Refer to the documentation in the [fastify-jwt-jwks](https://github.com/nearform/fastify-jwt-jwks) repository for general usage.  

## Installation

Just run:

```bash
npm install fastify-auth0-verify --save
```

## Usage

The configuration options for this plugin are similar to those in [fastify-jwt-jwks](https://github.com/nearform/fastify-jwt-jwks), except that this package accepts a `domain` option instead of `jwksUrl`:

- `domain`: The Auth0 tenant domain. It enables verification of RS256 encoded JWT tokens. It is also used to verify the token issuer (`iss`). Either provide a domain (`domain.com`) or the full URL, including the trailing slash (`https://domain.com/`).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md)

## Developer notes

### Tests

Tests are currently split into **unit** and **integration**. Integration tests need the following environment variables:

| Env var               |                                                             |
| --------------------- | ----------------------------------------------------------- |
| `AUTH0_DOMAIN`        | Auth0 dashboard -> application -> Settings -> Domain        |
| `AUTH0_CLIENT_ID`     | Auth0 dashboard -> application -> Settings -> Client ID     |
| `AUTH0_CLIENT_SECRET` | Auth0 dashboard -> application -> Settings -> Client Secret |
| `AUTH0_API_AUDIENCE`  | Auth0 application identifier                                |

## License

Copyright NearForm Ltd. Licensed under the [Apache-2.0 license](http://www.apache.org/licenses/LICENSE-2.0).

[![banner](https://raw.githubusercontent.com/nearform/.github/refs/heads/master/assets/os-banner-green.svg)](https://www.nearform.com/contact/?utm_source=open-source&utm_medium=banner&utm_campaign=os-project-pages)