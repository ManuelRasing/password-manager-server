import { FastifyPluginAsync } from 'fastify'
import fp from 'fastify-plugin'
import prisma from '../lib/prisma'
import { computeHmac, hashBody, isTimestampValid, safeEqual } from '../lib/hmac'
import '../types' // for FastifyRequest.userId augmentation

const auth: FastifyPluginAsync = async (app) => {
  app.addHook('preHandler', async (request, reply) => {
    const username  = request.headers['x-username']  as string | undefined
    const timestamp = request.headers['x-timestamp'] as string | undefined
    const signature = request.headers['x-signature'] as string | undefined

    if (!username || !timestamp || !signature) {
      return reply.status(401).send({ error: 'Missing authentication headers' })
    }

    if (!isTimestampValid(timestamp)) {
      return reply.status(401).send({ error: 'Request timestamp expired or invalid' })
    }

    // Look up the user — their apiKey is the HMAC secret.
    const user = await prisma.user.findUnique({ where: { username } })
    if (!user) {
      // Same 401 message as a bad signature — don't leak whether the username exists.
      return reply.status(401).send({ error: 'Invalid credentials' })
    }

    const bodyHash = hashBody(request.body)
    const expected = computeHmac(user.apiKey, request.method, request.url, timestamp, bodyHash)

    if (!safeEqual(expected, signature)) {
      return reply.status(401).send({ error: 'Invalid credentials' })
    }

    request.userId = user.id
  })
}

// fp() escapes Fastify encapsulation so this hook applies to the parent scope
export default fp(auth, { name: 'auth' })
