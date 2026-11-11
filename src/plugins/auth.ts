import { FastifyPluginAsync } from 'fastify'
import fp from 'fastify-plugin'
import { createHash } from 'node:crypto'
import prisma from '../lib/prisma'
import { computeHmac, hashBody, isTimestampValid, safeEqual } from '../lib/hmac'
import '../types' // for FastifyRequest.userId augmentation

const auth: FastifyPluginAsync = async (app) => {
  app.addHook('preHandler', async (request, reply) => {
    const authorization = request.headers.authorization
    if (authorization !== undefined) {
      const token = /^Bearer (pm_device_[A-Za-z0-9_-]{43})$/.exec(authorization)?.[1]
      if (!token || request.headers['x-username'] || request.headers['x-signature'] || request.headers['x-timestamp']) {
        return reply.status(401).send({ error: 'Invalid device access' })
      }
      const device = await prisma.deviceAccess.findUnique({
        where: { tokenHash: createHash('sha256').update(token).digest('hex') },
        select: { userId: true, revokedAt: true }
      })
      if (!device || device.revokedAt !== null) {
        return reply.status(401).send({ error: 'Invalid device access' })
      }
      if (request.method !== 'GET' || !request.routeOptions.config.allowDeviceRead) {
        return reply.status(403).send({ error: 'This device has read-only vault access' })
      }
      request.userId = device.userId
      return
    }

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
