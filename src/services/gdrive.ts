import { google } from 'googleapis'
import { Readable } from 'stream'

function getDriveClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET
  const refreshToken = process.env.GOOGLE_REFRESH_TOKEN
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID

  if (!clientId || !clientSecret || !refreshToken || !folderId) {
    throw new Error('Missing Google Drive env vars: GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN, GOOGLE_DRIVE_FOLDER_ID')
  }

  const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, 'http://localhost')
  oauth2Client.setCredentials({ refresh_token: refreshToken })

  return { drive: google.drive({ version: 'v3', auth: oauth2Client }), folderId }
}

export async function uploadBackupToDrive(filename: string, content: string): Promise<string> {
  const { drive, folderId } = getDriveClient()

  const response = await drive.files.create({
    requestBody: {
      name: filename,
      parents: [folderId],
      mimeType: 'application/json'
    },
    media: {
      mimeType: 'application/json',
      body: Readable.from(content)
    },
    fields: 'id, name, createdTime'
  })

  if (!response.data.id) throw new Error('Drive upload succeeded but returned no file ID')

  return response.data.id
}
