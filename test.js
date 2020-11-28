/* global describe, beforeEach, afterEach, beforeAll, afterAll, it, expect, jest */

'use strict'

const fastify = require('fastify')
const nock = require('nock')

/* eslint-disable max-len */

/*
How to regenerate the keys for RS256:

ssh-keygen -t rsa -b 4096 -m PEM -f private.key
openssl req -x509 -new -key private.key -out public.key -subj "/CN=unused"
*/

const jwks = {
  keys: [
    {
      alg: 'RS512',
      kid: 'KEY',
      x5c: ['UNUSED']
    },
    {
      alg: 'RS256',
      kid: 'KEY',
      x5c: [
        `
MIIEnjCCAoYCCQCMoDmTYrlYFTANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZ1
bnVzZWQwHhcNMTkxMTEyMTIzMjI0WhcNMTkxMjEyMTIzMjI0WjARMQ8wDQYDVQQD
DAZ1bnVzZWQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDK7ys6lJMZ
X5kt7NfsJHKHA7QXxmoixVw2lEPuyY/n4wg73+9IcyHmWUseb1AGHyXN1dD6GkcI
ujuFJdrzdsNuFsCQDB7YE0/ZH9sqBAp6A8qh42ZAG/A8VkMGkMzSypvEcinJ7USO
zYv9Q3BqKEAX41uE5dMRMVNQDEcHGxhoLwGpHECJgQ2NrRFK92WQvUuyJdoVF1hG
WXSWAGfTZUHLpG3FTK3175we8qBsqynkvegAOwzETLdExWt620dRl7gRp6hDfECH
69tdH6Qn1FC6fBKc1zvh79NA1iJrDCNJDFzN1bGVduPgOzsorhZSpt/ESw5YEOvC
QAHOtzNmVa+4SOOm/2eDs5X066YmmRGv9aNC5humBPwfKFdIJbhCeP6XBaG2vtSx
wfFEyfNCKoUTPUqdmj/CTW/TEFuzFab1hRLTmwOuLe2x3B0DuAkd/+auifXwDDPN
GVs+VySqWeu00hSVEzKZ9FdU0abGkmRqytj7xw8gPJ+jroq5ZFAyPtPUf8IpSubX
qAl0ppsqMrn9aMEEsu+APJi8yK4pEppWVZZBqf4/iPA+rR2J9uarUIsTQY8SKAeG
BpcOTEjXvW5nTLmAE2hse39qrT5xWp/PXxmsMR6Q3Dn/drlySoNlCGIi4L+BfS+Q
VZfm9BxIqS/aQW5TRMpeT7QAeK6NXD3dDwIDAQABMA0GCSqGSIb3DQEBCwUAA4IC
AQCEwcGqCjW0FDrRepfglTLLk699SjidT8+DvnXEwhN85PFT4U0ArEe5n3Cb6ray
qPEeOVG6QjLtGUZ9PRGVAjttfDQTAEWjqzJoqyAl60jj9Tm/G65UUbfHx37+Bvbc
jlQ1FqZ4Jr4b14uFOONh0WH92VRDR47k/WWaP5bjxbyCIGcGzohh2XyrtOtDU+hV
BntQ0w7736bL/MSunXO8tkx+LyM/Z4+HSWiwI+fcdIib27ZVFQ3W1NnRoufsSUqo
Noi2XJqr1oLbSGpagLiXsIr8UufOrpZ92Pool0/B4y/d6GbbK2UjxyHjGKB8fwNi
nU/+KAI1jPJT9dSc18u6F+cz4lQkGA9hmvApmiR7tTdcBWK/+m1lOHj4H8kZ2P/H
fZuOj1+GtJ+JTZO35d+GPJ41NVLDAm5gc3kGkDPt+XRZZLAtafPhMGK7jUzEgyLI
MITSqxjlBT++5VV035m84N+j5XJ0rYEHvgOmWJpJN+q/nIJpidq/6HzLOLoqmM5D
UGiOoOTZIj3/OfyolcYztNb+rYe3Ch/KbReC/h1sU/xqLJCImDyhHwSarjDdi8A3
dWxawCwETuA17mD7o/hsRUbXM6DHZekkuWPOL25UpRzlA1dtXMQ2ac83k+U6wyRs
7jYWkrpLCTpEJcQ0uGEQnsTsjr2oCq/KvNmDki+iMtvjhA==
        `.trim()
      ]
    }
  ]
}

const tokens = {
  hs256Valid:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ',
  hs256ValidWithIssuer:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.u9d0l3FrgAx4b9njutSd_HVnBc7gO4fzvl6TLMRUdpE',
  hs256ValidWithProvidedIssuer:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6ImZvbyJ9.ogCM7rsqPbUZHnoLz2LqkhA_wzTwgcqbIhjhN_B30iU',
  hs256ValidWithAudience:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImF1ZCI6ImZvbyJ9.o3mwcXxXgB03_exatmCTSJNd7IKA8fUxMwJ-YJgzfzo',
  hs256ValidWithDomainAsAudience:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.cMQz_ndIi2Kab0YJsGLOP-719lQ3cb7Cm9eMwfmeXmw',
  hs256InvalidSignature:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ-INVALID',

  rs256Valid:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.aw0Kohn2NgCOrYXn0kflRc2D_NVUgKLFb_3pgifHOxqFmGs27SF7ypRW7noMQLUNCorBApPsiKJtShUkGRbxHIN5dXy1gnEtoX2f5WgLnUQxd_gTtTGuzznJIE0nyqfLA6Kz_nkGuPOGV6jv-UAf8yB0iHXIVjCrYXWc0TpPD0OU56mZGi8RkrRewkEraopirGgSkVW5D449vzVd64Nxz6ZeRWZCAGvoWYPbttiyZ2TEKg4q5W7_dx2OY6JtapT2SebYVsZleGYlSE735NScnWRBOwWz8HkkUtu27ZwiIRgc40OPqEhWOkxhCwnmMfQyH-DkqVWaN92rKPciQBEst1rODG_jRiPw8XisMkpLY_k7pTuMN27WMPZb9HC33WZ3cAeCpauKpFT-UF-_NdXRy8RuEFE85T_7nT75f3qQlNp8XV2AUVTv3fdUqY9Z6n55cPjoLDTqS81bQZl2TxMaLh7-PQfHcJLrygpMDuW7AJkJjy7-N3CMEd1yFrQ-TjezAng5sxN56uOkbpsQMTc-2Pat_s4VOWWyALnyoFcMKR_aLG6qgxfqEihk1-bGB5G57pmeUEAzI-xwdy_NdRhZg7K9nfKIBPAoGgjxIyz5WA7p26RjVmCS5ZSnvk7mzK0vX0kXqvAnXAwXFrXbN5y1iU6omidM6BCqdsHIVBUTgtg',
  rs256ValidWithAudience:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyIsImF1ZCI6ImZvbyJ9.CC6GXyGOUjmnJqHezviamXsarWLYpNp9UlVwvuvdALJBjoexNSTz-S98AfEo1jZMOpPk_prc64aZjaROYUZUHf2EgfchowLhngAG6VUhcpU6BX23sKa8tz1ONLtVaTGfPua3Ju-p24vEjr5ZzD3zAhKx59zoVe4hdCPIh96HB-8RtBD7vJmnQur1nF0fEpYliSzkQjQXz_t2QregS5VVWLyJZZNWe7DpfiOVHQ5q8WIqX0Pec_SxXRIACB9KKw4KtxlUiVNXyGUi0WUkCWykZhI91JQJqYg_2k2eB4hAESobKJh1LkMHBUt116QZtBbdvautpN95XWQ9WV-S6kArOC6B3uQY5nQHYJJSSayoGd0Zm8eyK6gkim-GY3QNUcY6W0IHvH_xKyAXepu_w26nSRZJj1O7fkunOTlMILu_pTNV8E1jNB-wQz8HWfkCmkoJrbbdTLdJ3bRs5suCD5P4BWgFcNVcmgwQwvE0hfTt5n_0wfsbx_fXz_PXuC54fogcq0UNuH7sScsD4_GWgzjMzGrD6Qlgtbbr6N1bW6q1vTvjLbKLyxXbymm7ArYgqx3yIFF6AtGz5Je3BtkhP3AN8opdwDt7hwvTZl5CnJwAX7YeLcpqjPzD3GUI173RrjZFmool2rqTYEybM4iGd5PQEUJPepGhOkbUzCfr9JfGjJA',
  rs256ValidWithDomainAsAudience:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.smenUmykSpJCIrYDW9QQz9yBdrPv9mjOJO_uO0aS52bQqV_lcr9GdahXaDoZOgVm75kgGllKoNcd6LKgkE_QrAfqroB2eHmbv_h_fFvzQSpxEeeDjp6dVOhFhUvR-pp5fXuODMgIwU_DMu-TE-yDevsr2ryH5_OiHibRUTQ76dYbrHLvy2daat7WIR0jVa3S3j4Z_7sF-zrCyInAXAgmltm1bn6XB2_G2D6fwAgTV0iBPQJvZ6Cwhk9HbuhX6RtObz2cmCDx6VjU-FslLLATcS8-cptY51_MGFYUiJq42YHGEgWKllsawwyaT-NiuQekd1I_wMSeYlWN1OwWsE7nQ3bsAc8yvcnvEM5L0ugyvnr6aaiL8trUmBBcCaZd9AbJN6xVoWjbxdGf5VXtExUIQuiN8FvfPRrLS_ZTgCFz40qcVkyLN7Nh9X7TQU7EILKvkNkXKfAJ_mqVbJKpqKQYJvo5phE9aKhoNayT57-I3QznZuq-9iCTQryFw1C_zo5YrXrelJZJsv381QYatpkk2EAr_NjuQcDl9vrEdkjSBfOUz-ZSFOCN-qOoJDr_BE667IJ4XrKuWNbgm-Auoaja4rlb10y2flMDcxsRq_gc-W3GSb96luXJKMEUeNulbQMMmp0KrSMfvwC5a_4QjQmTlsAFe5ZOTc9C4n4mE8ouh-o',
  rs256InvalidSignature:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.aw0Kohn2NgCOrYXn0kflRc2D_NVUgKLFb_3pgifHOxqFmGs27SF7ypRW7noMQLUNCorBApPsiKJtShUkGRbxHIN5dXy1gnEtoX2f5WgLnUQxd_gTtTGuzznJIE0nyqfLA6Kz_nkGuPOGV6jv-UAf8yB0iHXIVjCrYXWc0TpPD0OU56mZGi8RkrRewkEraopirGgSkVW5D449vzVd64Nxz6ZeRWZCAGvoWYPbttiyZ2TEKg4q5W7_dx2OY6JtapT2SebYVsZleGYlSE735NScnWRBOwWz8HkkUtu27ZwiIRgc40OPqEhWOkxhCwnmMfQyH-DkqVWaN92rKPciQBEst1rODG_jRiPw8XisMkpLY_k7pTuMN27WMPZb9HC33WZ3cAeCpauKpFT-UF-_NdXRy8RuEFE85T_7nT75f3qQlNp8XV2AUVTv3fdUqY9Z6n55cPjoLDTqS81bQZl2TxMaLh7-PQfHcJLrygpMDuW7AJkJjy7-N3CMEd1yFrQ-TjezAng5sxN56uOkbpsQMTc-2Pat_s4VOWWyALnyoFcMKR_aLG6qgxfqEihk1-bGB5G57pmeUEAzI-xwdy_NdRhZg7K9nfKIBPAoGgjxIyz5WA7p26RjVmCS5ZSnvk7mzK0vX0kXqvAnXAwXFrXbN5y1iU6omidM6BCqdsHIVBUTgtg-INVALID',
  rs256MissingKey:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFOT1RIRVItS0VZIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyIsImF1ZCI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.wX-trsxG8LMeUbT7y0-rmQTLvTwnq-WnX9cbA5clnXK6iK0XWpiRRSbMK2MBAwR4IkkBvrrjblgnG-WBjz0-2H7hgjDJ41ehuYYFbpg-KgM37h7Fd-dwsMMUg7gv6adwXv6rAuHp-14FlW-OR6EmPaJwxxYgyT3ek7plVqbaI8v0W81vLduHwTDXSjEhVIWW9E2zX9zEIOQc22PkOOcAT8N2rqxF67sE-yBikXysT2AEVFNk_AT18qGq9WfPKKmD1Za19Y7_JvmcJQdsUj-5lnsEFNEtXi5hpaBdaBrXT2LwuWgILdrDwebiNMwz7iKK4r6zIHn5bR_XQPI8BR-SJSIZzZ8B089j-TwoWJyvaRCGALUceD--eErxVNZOxRTkqAWAtdG12xzlVRKCf3TY3X4h1mCtb4eOEvKddYzP8J24NwJM4ZYGIt7t59Fv9yZDGwjMxPvjW2f4Yrc63tH396_-sJZBIeXMOlC2NA3h94ud5vuFX30KODtP_t9ySKLiEFab8JXzYID9Ij-P6dcv1s6ylz0HD2tjzSCb_KCxlD63OFZWHxRvNe4kshKjdSVMft7ANaaT6BclfNjPPrl0e3uQ6NBCnW7VF9DXB1UBb7jqbPsPuWGOudQh-hov17dx-qPYv1eoGdt8CA46pZ2aY2K_KJaD17M0gHM4G9DFsqg',

  unsupportedAlgorithm:
    'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.nZU_gPcMXkWpkCUpJceSxS7lSickF0tTImHhAR949Z-Nt69LgW8G6lid-mqd9B579tYM8C4FN2jdhR2VRMsjtA',
  expired:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTQxNjIzOTAyMiwiZXhwIjoxNTExMjM5MDIyfQ.zTxEk-Z5qfP4n7U4jMU1gRvQEpl4HhnYTniTeQpaMkI',
  invalidAudience:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImF1ZCI6ImJhciJ9.Z0NHItgQv74Ce9re2q9qca_ifOn_cgndSaKBENZfN7M',
  invalidIssuer:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6ImJhciJ9.jG2FWFY709fd9ooB4NgU1YpPmT4gp_Ig8JisFZAOBS0'
}
/* eslint-enable max-len */

async function buildServer(options) {
  const server = fastify()

  server.register(require('.'), options)

  server.register(function (instance, options, done) {
    instance.get('/verify', {
      async handler(request) {
        return request.user
      },
      preValidation: instance.authenticate
    })

    instance.get('/decode', {
      async handler(request) {
        return {
          regular: request.jwtDecode(),
          full: request.jwtDecode({ complete: true })
        }
      }
    })

    done()
  })

  await server.listen(0)

  return server
}

describe('Options parsing', function () {
  it('should enable RS256 when the domain is present', async function () {
    const server = await buildServer({ domain: 'localhost' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['RS256'])

    server.close()
  })

  it('should enable HS256 when the secret is present', async function () {
    const server = await buildServer({ secret: 'secret' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['HS256'])

    server.close()
  })

  it('should enable both algorithms is both options are present', async function () {
    const server = await buildServer({ domain: 'http://localhost', secret: 'secret' })

    expect(server.auth0Verify.verify.algorithms).toEqual(['RS256', 'HS256'])

    server.close()
  })

  it('should complain if neither domain or secret are present', async function () {
    await expect(buildServer()).rejects.toThrow('Please provide at least one of the "domain" or "secret" options.')
  })

  it('should complain if forbidden options are present', async function () {
    await expect(buildServer({ algorithms: 'whatever' })).rejects.toThrow('Option "algorithms" is not supported.')
  })
})

describe('JWT token decoding', function () {
  let server

  beforeAll(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterAll(() => server.close())

  it('should decode a JWT token', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/decode',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      regular: {
        admin: true,
        name: 'John Doe',
        sub: '1234567890'
      },
      full: {
        header: {
          alg: 'HS256',
          typ: 'JWT'
        },
        payload: {
          admin: true,
          name: 'John Doe',
          sub: '1234567890'
        },
        signature: 'TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
      }
    })
  })

  it('should complain if the HTTP Authorization header is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode' })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Authorization HTTP header.'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization header should be in format: Bearer [token].'
    })
  })
})

describe('HS256 JWT token validation', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterEach(() => server.close())

  it('should make the token informations available through request.user', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({ sub: '1234567890', name: 'John Doe', admin: true })
  })

  it('should make the complete token informations available through request.user', async function () {
    await server.close()
    server = await buildServer({ secret: 'secret', complete: true })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      header: { alg: 'HS256', typ: 'JWT' },
      payload: { sub: '1234567890', name: 'John Doe', admin: true },
      signature: 'TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
    })
  })

  it('should validate the issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/'
    })
  })

  it('should validate provided issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', issuer: 'foo' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithProvidedIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'foo'
    })
  })

  it('should validate multiple issuers', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', issuer: ['bar', 'foo', 'blah'] })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithProvidedIssuer}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'foo'
    })
  })

  it('should validate the audience', async function () {
    await server.close()
    server = await buildServer({ audience: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({ sub: '1234567890', name: 'John Doe', admin: true, aud: 'foo' })
  })

  it('should validate the audience using the domain', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: true, secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256ValidWithDomainAsAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'https://localhost/'
    })
  })

  it('should reject an invalid signature', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.hs256InvalidSignature}` }
    })

    expect(response.statusCode).toEqual(401)

    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid token.'
    })
  })
})

describe('RS256 JWT token validation', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ domain: 'localhost', secret: 'secret' })
  })

  afterEach(() => server.close())

  beforeEach(function () {
    nock.disableNetConnect()

    nock('https://localhost/').get('/.well-known/jwks.json').reply(200, jwks)
  })

  afterEach(() => {
    nock.cleanAll()
    nock.enableNetConnect()
  })

  it('should make the token informations available through request.user', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/'
    })
  })

  it('should make the complete token informations available through request.user', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', complete: true })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      header: {
        alg: 'RS256',
        kid: 'KEY',
        typ: 'JWT'
      },
      payload: {
        sub: '1234567890',
        name: 'John Doe',
        admin: true,
        iss: 'https://localhost/'
      },
      signature:
        'aw0Kohn2NgCOrYXn0kflRc2D_NVUgKLFb_3pgifHOxqFmGs27SF7ypRW7noMQLUNCorBApPsiKJtShUkGRbxHIN5dXy1gnEtoX2f5WgLnUQxd_gTtTGuzznJIE0nyqfLA6Kz_nkGuPOGV6jv-UAf8yB0iHXIVjCrYXWc0TpPD0OU56mZGi8RkrRewkEraopirGgSkVW5D449vzVd64Nxz6ZeRWZCAGvoWYPbttiyZ2TEKg4q5W7_dx2OY6JtapT2SebYVsZleGYlSE735NScnWRBOwWz8HkkUtu27ZwiIRgc40OPqEhWOkxhCwnmMfQyH-DkqVWaN92rKPciQBEst1rODG_jRiPw8XisMkpLY_k7pTuMN27WMPZb9HC33WZ3cAeCpauKpFT-UF-_NdXRy8RuEFE85T_7nT75f3qQlNp8XV2AUVTv3fdUqY9Z6n55cPjoLDTqS81bQZl2TxMaLh7-PQfHcJLrygpMDuW7AJkJjy7-N3CMEd1yFrQ-TjezAng5sxN56uOkbpsQMTc-2Pat_s4VOWWyALnyoFcMKR_aLG6qgxfqEihk1-bGB5G57pmeUEAzI-xwdy_NdRhZg7K9nfKIBPAoGgjxIyz5WA7p26RjVmCS5ZSnvk7mzK0vX0kXqvAnXAwXFrXbN5y1iU6omidM6BCqdsHIVBUTgtg' // eslint-disable-line max-len
    })
  })

  it('should validate the audience', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'foo'
    })
  })

  it('should validate the audience using the domain', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: true, secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithDomainAsAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'https://localhost/'
    })
  })

  it('should validate with multiple audiences ', async function () {
    await server.close()
    server = await buildServer({
      domain: 'localhost',
      audience: ['https://otherhost/', 'foo', 'https://somehost/'],
      secret: 'secret'
    })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithAudience}` }
    })

    // expect(response.statusCode).toEqual(200)
    expect(JSON.parse(response.body)).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/',
      aud: 'foo'
    })
  })

  it('should reject an invalid signature', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256InvalidSignature}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid token.'
    })
  })

  it('should reject a token when is not possible to retrieve the JWK set due to a HTTP error', async function () {
    nock.cleanAll()

    nock('https://localhost/').get('/.well-known/jwks.json').reply(404, { error: 'Not found.' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'Unable to get the JWS due to a HTTP error: [HTTP 404] {"error":"Not found."}'
    })
  })

  it("should reject a token when the retrieved JWT set doesn't have the required key", async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'No matching key found in the set.'
    })
  })

  it('should reject a token when the retrieved JWT set returns an invalid key', async function () {
    nock.cleanAll()

    nock('https://localhost/')
      .get('/.well-known/jwks.json')
      .reply(200, {
        keys: [
          {
            alg: 'RS256',
            kid: 'KEY',
            x5c: ['FOO']
          }
        ]
      })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'error:09091064:PEM routines:PEM_read_bio_ex:bad base64 decode'
    })
  })

  it('should reject a token when is not possible to retrieve the JWK set due to a generic error', async function () {
    nock.cleanAll()
    nock.enableNetConnect()

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(JSON.parse(response.body)).toEqual({
      code: 'ECONNREFUSED',
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'request to https://localhost/.well-known/jwks.json failed, reason: connect ECONNREFUSED 127.0.0.1:443'
    })
  })

  it('should cache the key and not it the well-known URL more than once', async function () {
    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
  })

  it('should correctly get the key again from the well-known URL if cache expired', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', secretsTtl: 10 })

    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    await new Promise(resolve => setTimeout(resolve, 20))

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    const body = JSON.parse(response.body)

    expect(response.statusCode).toEqual(500)
    expect(body).toMatchObject({
      statusCode: 500,
      error: 'Internal Server Error'
    })

    expect(body.message).toMatch(/Nock: No match for request/)
  })

  it('should not cache the key if cache was disabled', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', secret: 'secret', secretsTtl: 0 })

    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    const body = JSON.parse(response.body)

    expect(response.statusCode).toEqual(500)
    expect(body).toMatchObject({
      statusCode: 500,
      error: 'Internal Server Error'
    })

    expect(body.message).toMatch(/Nock: No match for request/)
  })

  it('should not try to get the key twice when using caching if a previous attempt failed', async function () {
    let response

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'No matching key found in the set.'
    })

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(500)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 500,
      error: 'Internal Server Error',
      message: 'No matching key found in the set.'
    })
  })
})

describe('General error handling', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ secret: 'secret' })
  })

  afterEach(() => server.close())

  it('should complain if the HTTP Authorization header is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify' })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Authorization HTTP header.'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization header should be in format: Bearer [token].'
    })
  })

  it('should complain if the JWT token is malformed', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'Bearer FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid token.'
    })
  })

  it('should complain if the JWT token has an unsupported algorithm', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.unsupportedAlgorithm}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Unsupported token.'
    })
  })

  it('should complain if the JWT token has expired', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.expired}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Expired token.'
    })
  })

  it('should complain if the JWT token has an invalid issuer', async function () {
    await server.close()
    server = await buildServer({ domain: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.invalidIssuer}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid token.'
    })
  })

  it('should complain if the JWT token has an invalid audience', async function () {
    await server.close()
    server = await buildServer({ audience: 'foo', secret: 'secret' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.invalidAudience}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(JSON.parse(response.body)).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Invalid token.'
    })
  })
})

describe('Cleanup', function () {
  it('should close the cache when the server stops', async function (done) {
    jest.resetModules()
    expect.assertions(1)

    const mockCache = {
      close: jest.fn()
    }

    jest.doMock(
      'node-cache',
      jest.fn().mockImplementation(
        () =>
          function NodeCache() {
            return mockCache
          }
      )
    )

    const server = await buildServer({ secret: 'secret' })

    server.close(() => {
      expect(mockCache.close).toHaveBeenCalled()
      done()
    })
  })
})
