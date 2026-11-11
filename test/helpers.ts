import crypto from 'crypto'
import type { FastifyInstance } from 'fastify'
import { buildApp } from '../src/app'
import prisma from '../src/lib/prisma'
import { computeHmac, hashBody } from '../src/lib/hmac'
import { requireTestDatabaseUrl } from '../scripts/test-database'

function assertTestDatabase() {
  if (process.env.DATABASE_URL !== requireTestDatabaseUrl(process.env.TEST_DATABASE_URL)) {
    throw new Error('Integration tests require DATABASE_URL to match TEST_DATABASE_URL')
  }
}

/** Wipes all three tables. No DB-level FKs (relations are app-level), so order is free. */
export async function resetDb() {
  assertTestDatabase()
  await prisma.$transaction([
    prisma.credential.deleteMany(),
    prisma.vaultConfig.deleteMany(),
    prisma.user.deleteMany(),
  ])
}

/** Creates a user with a fresh random API key and returns it (key included). */
export async function createUser(username: string) {
  assertTestDatabase()
  const apiKey = crypto.randomBytes(32).toString('hex')
  const user = await prisma.user.create({ data: { username, apiKey } })
  return { ...user, apiKey }
}

/**
 * Builds the HMAC headers a real client would send.
 * Mirrors ApiService._signedHeaders on the mobile side and the server's own
 * hashBody (so the signature matches what the auth hook recomputes).
 */
export function signedHeaders(
  apiKey: string,
  username: string,
  method: string,
  path: string,
  body?: unknown,
  opts: { timestamp?: string } = {},
): Record<string, string> {
  const timestamp = opts.timestamp ?? Math.floor(Date.now() / 1000).toString()
  const bodyHash = hashBody(body)
  const signature = computeHmac(apiKey, method, path, timestamp, bodyHash)
  return {
    // Only set content-type when there is a body — matches the mobile client.
    // Sending it on a bodyless DELETE makes Fastify parse '' → 400.
    ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
    'x-username':   username,
    'x-timestamp':  timestamp,
    'x-signature':  signature,
  }
}

/** Builds the app with rate limiting + logging off (tests fire many requests). */
export function getTestApp(): FastifyInstance {
  assertTestDatabase()
  return buildApp({ rateLimit: false, logger: false })
}

/**
 * Admin header helper. No content-type — app.inject sets it automatically for
 * object payloads, and forcing it on bodyless DELETE/POST makes Fastify parse
 * '' → 400.
 */
export function adminHeaders(key = process.env.ADMIN_KEY): Record<string, string> {
  return { 'x-admin-key': key ?? '' }
}

export { prisma }
