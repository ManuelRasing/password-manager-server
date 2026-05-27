import { FastifyPluginAsync } from 'fastify'
import fp from 'fastify-plugin'
import { computeHmac, hashBody, isTimestampValid, safeEqual } from '../lib/hmac'

const auth: FastifyPluginAsync = async (app) => {
  app.addHook('preHandler', async (request, reply) => {
    const apiKey = process.env.API_KEY
    if (!apiKey) {
      return reply.status(500).send({ error: 'Server misconfigured: API_KEY not set' })
    }

    const timestamp = request.headers['x-timestamp'] as string | undefined
    const signature = request.headers['x-signature'] as string | undefined

    if (!timestamp || !signature) {
      return reply.status(401).send({ error: 'Missing authentication headers' })
    }

    if (!isTimestampValid(timestamp)) {
      return reply.status(401).send({ error: 'Request timestamp expired or invalid' })
    }

    const bodyHash = hashBody(request.body)
    const expected = computeHmac(apiKey, request.method, request.url, timestamp, bodyHash)

    if (!safeEqual(expected, signature)) {
      return reply.status(401).send({ error: 'Invalid signature' })
    }
  })
}

// fp() escapes Fastify encapsulation so this hook applies to the parent scope
export default fp(auth, { name: 'auth' })
