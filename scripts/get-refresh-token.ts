import 'dotenv/config'
import { google } from 'googleapis'
import * as http from 'http'
import * as url from 'url'

const clientId = process.env.GOOGLE_CLIENT_ID
const clientSecret = process.env.GOOGLE_CLIENT_SECRET

if (!clientId || !clientSecret) {
  console.error('Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env first')
  process.exit(1)
}

const PORT = 8080
const REDIRECT_URI = `http://localhost:${PORT}`

const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, REDIRECT_URI)

const authUrl = oauth2Client.generateAuthUrl({
  access_type: 'offline',
  scope: ['https://www.googleapis.com/auth/drive.file'],
  prompt: 'consent'
})

console.log('\n1. Open this URL in your browser:\n')
console.log(authUrl)
console.log('\nWaiting for Google to redirect back...\n')

const server = http.createServer(async (req, res) => {
  const { query } = url.parse(req.url ?? '', true)
  const code = query.code as string | undefined

  if (!code) {
    res.end('Missing authorization code. Close this tab and try again.')
    return
  }

  res.end('Authorization successful! You can close this tab and check your terminal.')
  server.close()

  try {
    const { tokens } = await oauth2Client.getToken(code)
    if (!tokens.refresh_token) {
      console.error('No refresh_token returned.')
      console.error('Revoke the app at https://myaccount.google.com/permissions and run this script again.')
      process.exit(1)
    }
    console.log('Add this to your .env and Render environment variables:\n')
    console.log(`GOOGLE_REFRESH_TOKEN="${tokens.refresh_token}"`)
  } catch (err) {
    console.error('Failed to exchange code for tokens:', err)
    process.exit(1)
  }
})

server.listen(PORT)
