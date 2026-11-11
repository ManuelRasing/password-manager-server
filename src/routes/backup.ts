import { FastifyInstance } from 'fastify'
import { credentialSelect, serializeCredential } from '../lib/credential'
import prisma from '../lib/prisma'
import { uploadBackupToDrive } from '../services/gdrive'

export async function backupRoutes(app: FastifyInstance) {
  app.post('/google-drive', async (req, reply) => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET || !process.env.GOOGLE_REFRESH_TOKEN || !process.env.GOOGLE_DRIVE_FOLDER_ID) {
      return reply.status(503).send({ error: 'Google Drive backup is not configured on this server' })
    }

    const user = await prisma.user.findUnique({ where: { id: req.userId } })
    const username = user?.username ?? req.userId

    const credentials = await prisma.credential.findMany({
      where:   { userId: req.userId, deletedAt: null },
      orderBy: { updatedAt: 'desc' },
      select: credentialSelect
    })

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const filename = `password-manager-backup-${username}-${timestamp}.json`

    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      count: credentials.length,
      credentials: credentials.map(serializeCredential)
    }, null, 2)

    const fileId = await uploadBackupToDrive(filename, payload)

    return reply.send({
      success: true,
      fileId,
      filename,
      count: credentials.length,
      exportedAt: new Date().toISOString()
    })
  })
}
