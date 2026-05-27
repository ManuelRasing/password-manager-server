import { FastifyInstance } from 'fastify'
import prisma from '../lib/prisma'
import { uploadBackupToDrive } from '../services/gdrive'

export async function backupRoutes(app: FastifyInstance) {
  app.post('/google-drive', async (_req, reply) => {
    if (!process.env.GOOGLE_SERVICE_ACCOUNT_JSON || !process.env.GOOGLE_DRIVE_FOLDER_ID) {
      return reply.status(503).send({ error: 'Google Drive backup is not configured on this server' })
    }

    const credentials = await prisma.credential.findMany({
      orderBy: { updatedAt: 'desc' },
      select: {
        id: true,
        siteName: true,
        usernameHint: true,
        encryptedPayload: true,
        iv: true,
        createdAt: true,
        updatedAt: true
      }
    })

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const filename = `password-manager-backup-${timestamp}.json`

    const payload = JSON.stringify({
      exportedAt: new Date().toISOString(),
      count: credentials.length,
      // Note: siteName and usernameHint are stored as plaintext metadata.
      // encryptedPayload values are AES-256-GCM ciphertext — unreadable without the master password.
      credentials
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
