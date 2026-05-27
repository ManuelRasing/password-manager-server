import 'dotenv/config'
import Fastify from 'fastify'
import rateLimit from '@fastify/rate-limit'
import authPlugin from './plugins/auth'
import { credentialRoutes } from './routes/credentials'

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    // Never log auth headers or encrypted payloads
    redact: [
      'req.headers["x-signature"]',
      'req.headers["x-timestamp"]',
      'req.body.encryptedPayload',
      'req.body.iv'
    ]
  }
})

async function start() {
  // Rate limiting — applies to all routes
  await app.register(rateLimit, {
    max: 20,
    timeWindow: '1 minute',
    errorResponseBuilder: (_req, context) => ({
      error: 'Too many requests',
      retryAfter: context.after
    })
  })

  // Public route — no auth required
  app.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }))

  // Authenticated scope — all routes below require valid HMAC signature
  app.register(async (protectedScope) => {
    protectedScope.register(authPlugin)
    protectedScope.register(credentialRoutes, { prefix: '/credentials' })
  })

  const port = parseInt(process.env.PORT ?? '3000', 10)
  await app.listen({ port, host: '0.0.0.0' })
}

start().catch(err => {
  app.log.error(err)
  process.exit(1)
})
