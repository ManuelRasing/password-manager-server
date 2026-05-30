import 'dotenv/config'
import prisma from './lib/prisma'
import { buildApp } from './app'

const app = buildApp()

/**
 * One-shot migration: if no users exist yet but legacy single-tenant data does,
 * create an "admin" user owning the existing API_KEY and assign all "migrating"
 * rows to it. Idempotent — runs only when the User table is empty.
 */
async function bootstrapAdminIfNeeded() {
  const userCount = await prisma.user.count()
  if (userCount > 0) return

  const apiKey = process.env.API_KEY
  if (!apiKey) {
    app.log.warn('[bootstrap] No users and no API_KEY — skipping admin bootstrap')
    return
  }

  const admin = await prisma.user.create({
    data: { username: 'admin', apiKey }
  })

  const [credUpdate, vaultUpdate] = await prisma.$transaction([
    prisma.credential.updateMany({
      where: { userId: 'migrating' },
      data:  { userId: admin.id }
    }),
    prisma.vaultConfig.updateMany({
      where: { userId: 'migrating' },
      data:  { userId: admin.id }
    })
  ])

  app.log.info(
    `[bootstrap] Created admin user (id=${admin.id}). ` +
    `Reassigned ${credUpdate.count} credentials and ${vaultUpdate.count} vault config(s). ` +
    `Update the mobile Settings: Username = "admin", API Key = your existing API_KEY.`
  )
}

async function start() {
  await bootstrapAdminIfNeeded()
  const port = parseInt(process.env.PORT ?? '3000', 10)
  await app.listen({ port, host: '0.0.0.0' })
}

start().catch(err => {
  app.log.error(err)
  process.exit(1)
})
