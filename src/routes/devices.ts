import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'

export async function deviceRoutes(app: FastifyInstance) {
  app.get('/', async (request) => prisma.deviceAccess.findMany({
    where: { userId: request.userId },
    orderBy: { createdAt: 'desc' },
    select: { id: true, deviceName: true, createdAt: true, revokedAt: true }
  }))

  app.delete<{ Params: { id: string } }>('/:id', {
    schema: {
      params: {
        type: 'object',
        required: ['id'],
        properties: { id: { type: 'string', minLength: 1, maxLength: 128 } },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    const where = { id: request.params.id, userId: request.userId }
    const revoked = await prisma.deviceAccess.updateMany({
      where: { ...where, revokedAt: null },
      data: { revokedAt: new Date() }
    })
    if (revoked.count === 0 && !await prisma.deviceAccess.findFirst({
      where, select: { id: true }
    })) {
      return reply.status(404).send({ error: 'Device not found' })
    }
    return reply.status(204).send()
  })
}
