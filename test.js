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
        `MIIFAzCCAuugAwIBAgIUVVehdczwTU8GW39JULd9pYi43ZkwDQYJKoZIhvcNAQEL
        BQAwETEPMA0GA1UEAwwGdW51c2VkMB4XDTIxMTEzMDA5MDYyMVoXDTIxMTIzMDA5
        MDYyMVowETEPMA0GA1UEAwwGdW51c2VkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
        MIICCgKCAgEAwvS4K8Jnx2b1nuab16/cEslS5HqvKS/Qs7+9X3B9RdC5fT//lyWQ
        1lj4Ag9rX+ewzfBjZksgtfYAp5gmXJl/+E+dYEIry2XkC2AJZ9voqTa+hld6a8YW
        OmvITSNc8GinP73gXBcwcv20Ligyg3c7LTn5ZSaNwJixpgsi9/3qz0WK9ArylHgD
        LQ4hEEKMicYvSWoC6VnnWANKZ0EphyXYplie0EdEbcoje0+7qncu64Mm2LwYaFW3
        RR1ZwrmzCUjX2MV3/L2h/gI3kSIgrkxSZS0gdcvFO9uAu5tfcJbpJj9NR+ynH4CL
        Rl8OT8F4lyCdO55QTJUMUDb1zLDurVLOWYvfxVejsvmz3/tQy+/T9uV2dFBzOx9I
        AbcI+kjGSCF+APi/ShDnME8nnkxKMTC/NO2wC2sAqgwhH+4fl1Lb2lyIUrwmWVEG
        JBajQ26j/iGUGGlpZW3dWHa7NKtVE5bS1U5HBBWuqPlyMqhr4Pa053uJ678ywGpk
        yQan1E00YP67u36HAP8hNZtXWPTvHRasek8nEeKcemfFcu563eqaPjbCkieE0yUe
        6m6OU5tD8TM+Gbce1OievtPEcJrctb+xoFZNZ0k4gTUIqyJ3F/n3o1x5wYFdf/wi
        9feoTOr2kfhFQqarFPUZAgKqOKANRZdsl54TkApTmpWvtrpXOfYoUlUCAwEAAaNT
        MFEwHQYDVR0OBBYEFDwRuiSKlx21kCz3yeZGxM+Qw9b0MB8GA1UdIwQYMBaAFDwR
        uiSKlx21kCz3yeZGxM+Qw9b0MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
        BQADggIBAAWS2FZI+ISovVC1gIbK+JAMlTGPpuawMe2N/38zLK1TUdA10rLqyQbF
        31Sv/wj6IV6PDkuDhH3BzB04gQ0ZrIorqYG9wR3Y4ekcCr7pCkTbKo18I6TI7p3U
        PN1t7W1VBt6PeXsXob+uhORhVtJH8+qqQswRlwobp9tF0xELJWHqs2JbWrfikb1R
        tKv9IpsTXIyxab6iBGew4NLiGLEpk03ghjQLFWxC4/yvcF0TqZmSMO1IXDjSiK8t
        6iBgLJFdyhSV7BTmHOV4ibdaEHdAfWmm4WvyQnHUZHIg4YgQuiyykqBHS1CLTIW4
        sUjdDPJNTS7DKsKHrZUPnaOwQTRkkhjwC5tL6Fal+o8z1ogzbWJhhGeqq+KX6/Xb
        K/NGMUhMdexh3fPmJ3wlEI2Ck7uni3CpPGnwckcoFpccwQjnkFj4TxhWDtf1yLxr
        ne8EcVGQ9uuwsJjVboaujCovHChaRailpbBIV5Sc789iyLSZf+ylHv4dJcQ8UNJX
        Wxqt7yJcfPnPGA3WGbvaJJuKtsWREE+Mf3ex7HL/RpX+6FX10m5GlwGKTNd0h2b8
        qFPjP1tPZemAqxQntUkEGizSYxQ1bajAgrMjXeVNqz3Bah3WE7+pFbsH39h7fhtJ
        L4HPfzHnmwS227fhAllgr8d7gc9vPgzLi9hKq6PMHqHRTPlytNMl`.trim()
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
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.vTYivYeaq09ZqDltEg7ELc6CXAWAg78LjmG-g7pqEm9xCIJ9amCS9tGfo_bwnAdr-VYb96vAVsZQfWVROQExGZCj6OxDxrZNcwN0Dv62axRhT2TrDKG9qzZMt_Lt92oLTVG0o3FAM8v_ZztjA5u2AMYWAA4xHuuj5Jf1ZbSIL7L0J5MJ62yg1xY2pV_5jUoVORBLo2XW7WtUkYZRrq4_tsAE5LgwSF83SPkScAF2p-MYOtz3RsjlAfGSAj5WyF4MnGCuQeC4jxH_UrpIf43cQpVliA-vRKr3hH_mPrnU-S8hI-acM69z_yfO3P28H_cn7Lc3sg6MGKJhuM4us1BWfYafDxdqbSaIvjKNCXaPxWSLgwOhEmjovNfluPRWnNR6CT3qEg3g7Mkobj1QKIbw8bO0UzpKBZHQEqLP_MJnHlGEG8m0tHIpD3GKJnVmlepX-0w1DtE02hdYOlr40E-LfOlTAFpMHkPvCsO6LdDkGILAvtng0qUXmHsKkCw18BgdS9_z9e9NqSOmuCxqeEdq41rFgjdKXjb8qCiTdDsip65zq__onsL_ugG-oHOBurzvmkClVY6H4JiKv-BIPueZHwe-SYxdb2aBzgaS85calY_zf2Otmy1E2FE-0D4V3OwJ2JaJGcvSnDcWdHC2BVCQQ4U4bEuASX_EJv52mn-R6r8',
  rs256ValidWithAudience:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJwYXlsb2FkIjp7InN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIiwiYXVkIjoiZm9vIn19.bOf8yPkFz00m662SVzERGjFOemI666MOybiMseYJRRTsNAlVU3HiGNV-yzNxbyp87LI04XgJmIcSRq7T7ScbXRUk6TjXxXXLJsmCeoOMgu5o_zZQJBVgrmXMMl9adpsHeyK5gBlSWNyDY9AVuxrRSmvTSiBbbRe6GhT2SW2vmSAZi6G3CEWjTUL4bxoMV3VtykPq4mGvPpnJ8GnlybrDDZtSuw0Dncm0PVmYVYQXLlCzjNPI6LAcRzTh7rpDpSbcrOQxftX9VgpfXkIFXxnA4Yq7f7SfkQhZQDGIEzOvTs7pppF7uHFoCVdNXHzyMh3ck4PT00A_JQYxfVO8qksWFkLH0kjgcM7QfVz9BBF2Bl11OCNkfOkUJ-ZMUf2jq86GtcxbVtufciTu5KNg6jQolxhv1NRn9qXiO6D1wTiQhh336l1kZq5Jn2IV8r-Ezp8PvHgeEHSRN3yQcvbm1bDw9MMBz3QW3I71VEQGXAdANxMCzmN390gMX01JI9xO6T_t74AmX6qdgp5PSXiHiiDkwEqRPwamMMkniinmzxVUunTGlZob5ZZ29gbMBOC9B0o3HNloeciBq5Gii8Msiyv9_t_JYxUy0bjYUwRw129uo_HwE2j22RUe-rcGi7VNeH8eiF3_cZ6ZOGK6juQcfcACujS_8PgO5gWOY9JbvDTNxFc',
  rs256ValidWithDomainAsAudience:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJwYXlsb2FkIjp7InN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIn19.WezQCeZUzPHwFCo-f9QyCidjRjx9A5mpMRSh_1YkpHRcBN8WYKk4Z7qa9_YVMlBCKUxmxcDY0uWzEWfGThH5dickju-iMH8LKuDEZFF8bT8c-HkWzokPqvlZHfUZN-3sBm7JMfWRa42aZrzrKVmBpe_qhkpqJBi62AuScSswUfno0dDmvNZHFyCRRLGg16uFjGQJ6xiWDGcV-EMFWTj8HqVeDdp6EWHCrl7OvbCRS2uz5XG70jzrNSMShjeXIPZDDG3DE3-pzOU89h6qI5tA6ScCl0cFxWei0l54yFGtR1qMGnqVsBAkTjhZsPl3LM_d_AqfpGImAcf32dT2pFZYJn2Q428ceJZdlBW2p4gLyLUHmCS2B7FRnyOu0r0bm8M3CQ5baNMOKMJzLDvelmlZsOYQ19D6868PqEapVZ9nRWuq5lZW6PD5Fz16TnSBrQ04Iy6FNxUpqp8zZShPp4ozAzbh9pOnHXba9N2EnNp9h8f4zmkAoPuU1A17zdtUoCDskydDDB9CANOVh4poN2RK-xzHvtV6rpBxRUGhVX8ZQaucnsiXCNaoke1eNKMJ_Yl0ReJcE2xVDpPDpInY4mHlTQp2-PMD_ZWdM-delLgE587rO_wcMP0O1W_yNtj-1Do1zpjkIU3-089XSK0oNFz4F7F_nHrcJUSAPG8gE_lHET0',
  rs256InvalidSignature:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktFWSJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlzcyI6Imh0dHBzOi8vbG9jYWxob3N0LyJ9.aw0Kohn2NgCOrYXn0kflRc2D_NVUgKLFb_3pgifHOxqFmGs27SF7ypRW7noMQLUNCorBApPsiKJtShUkGRbxHIN5dXy1gnEtoX2f5WgLnUQxd_gTtTGuzznJIE0nyqfLA6Kz_nkGuPOGV6jv-UAf8yB0iHXIVjCrYXWc0TpPD0OU56mZGi8RkrRewkEraopirGgSkVW5D449vzVd64Nxz6ZeRWZCAGvoWYPbttiyZ2TEKg4q5W7_dx2OY6JtapT2SebYVsZleGYlSE735NScnWRBOwWz8HkkUtu27ZwiIRgc40OPqEhWOkxhCwnmMfQyH-DkqVWaN92rKPciQBEst1rODG_jRiPw8XisMkpLY_k7pTuMN27WMPZb9HC33WZ3cAeCpauKpFT-UF-_NdXRy8RuEFE85T_7nT75f3qQlNp8XV2AUVTv3fdUqY9Z6n55cPjoLDTqS81bQZl2TxMaLh7-PQfHcJLrygpMDuW7AJkJjy7-N3CMEd1yFrQ-TjezAng5sxN56uOkbpsQMTc-2Pat_s4VOWWyALnyoFcMKR_aLG6qgxfqEihk1-bGB5G57pmeUEAzI-xwdy_NdRhZg7K9nfKIBPAoGgjxIyz5WA7p26RjVmCS5ZSnvk7mzK0vX0kXqvAnXAwXFrXbN5y1iU6omidM6BCqdsHIVBUTgtg-INVALID',
  rs256MissingKey:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkFOT1RIRVItS0VZIn0.eyJwYXlsb2FkIjp7InN1YiI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIiwiYXVkIjoiaHR0cHM6Ly9sb2NhbGhvc3QvIn19.jZrn8F1RClAbb4P1JJR0XJ0KTw0U7DqQEd098AQhxjojb-6BfGwxABn-hIrFeQhDPs1-RtzCfoRJ0WvA40UoqAPf071gdlB5FFq95lUO_9B8XXby0ueUe-RdlqMkP3HvukLLFhQW481zBEVAyp8xSz-P1LsYHk6avCA1lAGMKZoh6FOsoE-cyBMKF0koc2MWUPvu6BYr48gyX50QKBr_yrSdfLgQj67tcMicvESddwZX1ggr7eF4ZeHXVZV_F_AMkOywiEkiS4EvC2gywNJkbIz3eLqsQFYYzUhMsQfu5x-YfSw3-pmEtw7SQZ-QeP2zs1sZP0tcJJ03ya-dcG1E7IindR1eAoji6CYtRElF0DMsIgV-Cd6NB1Vx5R-Le15MROuvArGisJKOlHYf79g1-1hWC5LAtQ0eAR5gkeRRX6UjUL_kCMVtf69qed74mq-nA4P2BNW72CL9SzjPwmNeUVfGdui10NLMt9QAs8jcYksgeMiMoQW6NVvsc9ptKmynmTJzCEP1s-Jgv0erMIIe5_mU9YnihZHJ19dL7BDvg0YV_tP3i6vRXqJsYBx43YPKMwiI5OKRSregfRLvq66JSlL7k2hfIVRLhJc-tvaxoeewDJc1qksc-qgsBWwQ7lVpQlj_mBbmzujXmj99nQJfqpV9iPS5WPPCbtJTeTlXcP8',

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
  server.register(require('fastify-cookie'))
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
          regular: await request.jwtDecode(),
          full: await request.jwtDecode({ decode: { complete: true } })
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
    expect(response.json()).toEqual({
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
        input:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9',
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
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.headers'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(400)
    expect(response.json()).toEqual({
      statusCode: 400,
      error: 'Bad Request',
      message: 'Format is Authorization: Bearer [token]'
    })
  })
})

describe('JWT cookie token decoding', function () {
  let server

  beforeAll(async function () {
    server = await buildServer({ secret: 'secret', token: 'token', cookie: { cookieName: 'token' } })
  })

  afterAll(() => server.close())

  it('should decode a JWT token from cookie', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/decode',
      cookies: {
        token: tokens.hs256Valid
      }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
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
        input:
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9',
        payload: {
          admin: true,
          name: 'John Doe',
          sub: '1234567890'
        },
        signature: 'TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
      }
    })
  })

  it('should complain if the JWT token cookie is missing', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', cookies: { foo: 'bar' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.cookies'
    })
  })

  it('should complain if the JWT token cookie is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/decode', cookies: { foo: 'bar' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'No Authorization was found in request.cookies'
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
    expect(response.json()).toEqual({ sub: '1234567890', name: 'John Doe', admin: true })
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
    expect(response.json()).toEqual({
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
    expect(response.json()).toEqual({
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
    expect(response.json()).toEqual({
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
    expect(response.json()).toEqual({
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
    expect(response.json()).toEqual({ sub: '1234567890', name: 'John Doe', admin: true, aud: 'foo' })
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
    expect(response.json()).toEqual({
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

    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The token signature is invalid.'
    })
  })
})

describe('RS256 JWT token validation', function () {
  let server

  beforeEach(async function () {
    server = await buildServer({ domain: 'https://localhost/' })
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
    expect(response.json()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iss: 'https://localhost/'
    })
  })

  it('should make the complete token informations available through request.user', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', complete: true })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256Valid}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
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
        'vTYivYeaq09ZqDltEg7ELc6CXAWAg78LjmG-g7pqEm9xCIJ9amCS9tGfo_bwnAdr-VYb96vAVsZQfWVROQExGZCj6OxDxrZNcwN0Dv62axRhT2TrDKG9qzZMt_Lt92oLTVG0o3FAM8v_ZztjA5u2AMYWAA4xHuuj5Jf1ZbSIL7L0J5MJ62yg1xY2pV_5jUoVORBLo2XW7WtUkYZRrq4_tsAE5LgwSF83SPkScAF2p-MYOtz3RsjlAfGSAj5WyF4MnGCuQeC4jxH_UrpIf43cQpVliA-vRKr3hH_mPrnU-S8hI-acM69z_yfO3P28H_cn7Lc3sg6MGKJhuM4us1BWfYafDxdqbSaIvjKNCXaPxWSLgwOhEmjovNfluPRWnNR6CT3qEg3g7Mkobj1QKIbw8bO0UzpKBZHQEqLP_MJnHlGEG8m0tHIpD3GKJnVmlepX-0w1DtE02hdYOlr40E-LfOlTAFpMHkPvCsO6LdDkGILAvtng0qUXmHsKkCw18BgdS9_z9e9NqSOmuCxqeEdq41rFgjdKXjb8qCiTdDsip65zq__onsL_ugG-oHOBurzvmkClVY6H4JiKv-BIPueZHwe-SYxdb2aBzgaS85calY_zf2Otmy1E2FE-0D4V3OwJ2JaJGcvSnDcWdHC2BVCQQ4U4bEuASX_EJv52mn-R6r8' // eslint-disable-line max-len
    })
  })

  it('should validate the audience', async function () {
    await server.close()
    server = await buildServer({ domain: 'localhost', audience: 'foo' })

    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256ValidWithAudience}` }
    })

    expect(response.statusCode).toEqual(200)
    expect(response.json()).toEqual({
      payload: {
        sub: '1234567890',
        name: 'John Doe',
        admin: true,
        iss: 'https://localhost/',
        aud: 'foo'
      }
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
    expect(response.json()).toEqual({
      payload: {
        sub: '1234567890',
        name: 'John Doe',
        admin: true,
        iss: 'https://localhost/',
        aud: 'https://localhost/'
      }
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
    expect(response.json()).toEqual({
      payload: {
        sub: '1234567890',
        name: 'John Doe',
        admin: true,
        iss: 'https://localhost/',
        aud: 'foo'
      }
    })
  })

  it('should reject an invalid signature', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256InvalidSignature}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The token signature is invalid.'
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
    expect(response.json()).toEqual({
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

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
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
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: Unsupported PEM public key.'
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
    expect(response.json()).toEqual({
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

    const body = response.json()

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

    const body = response.json()

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

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
    })

    response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.rs256MissingKey}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Key: Public key must be provided'
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
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Missing Authorization HTTP header.'
    })
  })

  it('should complain if the HTTP Authorization header is in the wrong format', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization header should be in format: Bearer [token].'
    })
  })

  it('should complain if the JWT token is malformed', async function () {
    const response = await server.inject({ method: 'GET', url: '/verify', headers: { Authorization: 'Bearer FOO' } })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'The token is malformed.'
    })
  })

  // it('should complain if the JWT token has an unsupported algorithm', async function () {
  //   const response = await server.inject({
  //     method: 'GET',
  //     url: '/verify',
  //     headers: { Authorization: `Bearer ${tokens.unsupportedAlgorithm}` }
  //   })

  //   expect(response.statusCode).toEqual(401)
  //   expect(response.json()).toEqual({
  //     statusCode: 401,
  //     error: 'Unauthorized',
  //     message: 'The token algorithm is invalid.'
  //   })
  // })

  it('should complain if the JWT token has expired', async function () {
    const response = await server.inject({
      method: 'GET',
      url: '/verify',
      headers: { Authorization: `Bearer ${tokens.expired}` }
    })

    expect(response.statusCode).toEqual(401)
    expect(response.json()).toEqual({
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
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The iss claim value is not allowed.'
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
    expect(response.json()).toEqual({
      statusCode: 401,
      error: 'Unauthorized',
      message: 'Authorization token is invalid: The aud claim value is not allowed.'
    })
  })
})

describe('Cleanup', function () {
  it('should close the cache when the server stops', function (done) {
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

    buildServer({ secret: 'secret' }).then(server => {
      server.close(() => {
        expect(mockCache.close).toHaveBeenCalled()
        done()
      })
    }, done)
  })
})
