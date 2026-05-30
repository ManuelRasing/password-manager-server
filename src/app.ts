import Fastify, { FastifyInstance } from 'fastify'
import rateLimit from '@fastify/rate-limit'
import authPlugin from './plugins/auth'
import { credentialRoutes } from './routes/credentials'
import { backupRoutes } from './routes/backup'
import { vaultConfigRoutes } from './routes/vault-config'
import { adminRoutes } from './routes/admin'

export interface BuildAppOptions {
  /** Disable rate limiting (tests fire many requests in a tight loop). */
  rateLimit?: boolean
  /** Quiet logger for tests. */
  logger?: boolean
}

/**
 * Builds the Fastify app with all routes registered but does NOT call listen().
 * Shared by the production entrypoint (index.ts) and the test suite (app.inject).
 */
export function buildApp(opts: BuildAppOptions = {}): FastifyInstance {
  const { rateLimit: enableRateLimit = true, logger = true } = opts

  const app = Fastify({
    logger: logger
      ? {
          level: process.env.LOG_LEVEL ?? 'info',
          // Never log auth headers or encrypted payloads
          redact: [
            'req.headers["x-signature"]',
            'req.headers["x-timestamp"]',
            'req.headers["x-username"]',
            'req.headers["x-admin-key"]',
            'req.body.encryptedPayload',
            'req.body.iv'
          ]
        }
      : false
  })

  app.register(async (root) => {
    if (enableRateLimit) {
      await root.register(rateLimit, {
        max: 20,
        timeWindow: '1 minute',
        errorResponseBuilder: (_req, context) => ({
          error: 'Too many requests',
          retryAfter: context.after
        })
      })
    }

    // Public route — no auth required
    root.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }))

    // Admin scope — secured by ADMIN_KEY (separate from per-user API keys)
    root.register(async (adminScope) => {
      adminScope.register(adminRoutes, { prefix: '/admin' })
    })

    // Authenticated scope — all routes below require valid HMAC signature + X-Username
    root.register(async (protectedScope) => {
      protectedScope.register(authPlugin)
      protectedScope.register(credentialRoutes,  { prefix: '/credentials' })
      protectedScope.register(backupRoutes,      { prefix: '/backup' })
      protectedScope.register(vaultConfigRoutes, { prefix: '/vault-config' })
    })
  })

  return app
}
