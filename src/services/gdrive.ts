import { google } from 'googleapis'
import { Readable } from 'stream'

function getDriveClient() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON
  const folderId = process.env.GOOGLE_DRIVE_FOLDER_ID

  if (!raw || !folderId) {
    throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON and GOOGLE_DRIVE_FOLDER_ID must be set')
  }

  const credentials = JSON.parse(raw)

  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: ['https://www.googleapis.com/auth/drive.file']
  })

  return { drive: google.drive({ version: 'v3', auth }), folderId }
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
