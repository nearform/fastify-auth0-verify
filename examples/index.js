const Fastify = require('fastify')

async function run({ token, ...options }) {
  if (!token) {
    throw new Error('Please provide a token via --token {token}')
  }

  const fastify = Fastify()

  await fastify.register(require('..'), options)

  fastify.get(
    '/',
    {
      preValidation: fastify.authenticate
    },
    r => r.user
  )

  const response = await fastify.inject({
    url: '/',
    headers: {
      Authorization: `Bearer ${token}`
    }
  })

  console.log('\n==============\n|  Response  |\n==============\n')
  console.log(JSON.stringify(JSON.parse(response.body), null, 2))
}

run(
  process.argv
    .slice(2)
    .map((o, i, _) => !(i % 2) && [o, _[i + 1]])
    .filter(Boolean)
    .reduce((o, [k, v]) => Object.assign(o, { [k.replace(/^--/, '')]: v }), {})
)
