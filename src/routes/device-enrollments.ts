import { createHash, randomBytes } from 'node:crypto'
import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'

const enrollmentLifetimeMs = 5 * 60 * 1000

export async function deviceEnrollmentRoutes(app: FastifyInstance) {
  app.post<{ Body: { deviceName: string } }>('/', {
    schema: {
      body: {
        type: 'object',
        required: ['deviceName'],
        properties: { deviceName: { type: 'string', minLength: 1, maxLength: 64 } },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    const deviceName = request.body.deviceName.trim()
    if (!deviceName) return reply.status(400).send({ error: 'A device name is required' })
    const code = randomBytes(16).toString('base64url')
    const expiresAt = new Date(Date.now() + enrollmentLifetimeMs)
    await prisma.deviceEnrollment.create({
      data: {
        userId: request.userId,
        codeHash: createHash('sha256').update(code).digest('hex'),
        deviceName,
        expiresAt
      }
    })
    return reply.header('Cache-Control', 'no-store').status(201).send({ code, expiresAt })
  })
}

export async function publicDeviceEnrollmentRoutes(app: FastifyInstance) {
  app.post<{ Body: { code: string } }>('/redeem', {
    schema: {
      body: {
        type: 'object',
        required: ['code'],
        properties: { code: { type: 'string', pattern: '^[A-Za-z0-9_-]{22}$' } },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    const codeHash = createHash('sha256').update(request.body.code).digest('hex')
    const deviceToken = `pm_device_${randomBytes(32).toString('base64url')}`
    const device = await prisma.$transaction(async (transaction) => {
      const enrollment = await transaction.deviceEnrollment.findUnique({
        where: { codeHash },
        select: { id: true, userId: true, deviceName: true }
      })
      if (!enrollment) return null
      const now = new Date()
      const claimed = await transaction.deviceEnrollment.updateMany({
        where: { id: enrollment.id, consumedAt: null, expiresAt: { gt: now } },
        data: { consumedAt: now }
      })
      if (claimed.count !== 1) return null
      return transaction.deviceAccess.create({
        data: {
          userId: enrollment.userId,
          deviceName: enrollment.deviceName,
          tokenHash: createHash('sha256').update(deviceToken).digest('hex')
        },
        select: { id: true, deviceName: true }
      })
    })
    if (!device) return reply.status(401).send({ error: 'Enrollment code is invalid, expired, or already used' })
    return reply.header('Cache-Control', 'no-store').status(201).send({
      deviceId: device.id,
      deviceName: device.deviceName,
      deviceToken
    })
  })
}
