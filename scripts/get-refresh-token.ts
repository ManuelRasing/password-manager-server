import 'dotenv/config'
import { google } from 'googleapis'
import * as readline from 'readline'

const clientId = process.env.GOOGLE_CLIENT_ID
const clientSecret = process.env.GOOGLE_CLIENT_SECRET

if (!clientId || !clientSecret) {
  console.error('Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env first')
  process.exit(1)
}

const oauth2Client = new google.auth.OAuth2(clientId, clientSecret, 'http://localhost')

const authUrl = oauth2Client.generateAuthUrl({
  access_type: 'offline',
  scope: ['https://www.googleapis.com/auth/drive.file'],
  prompt: 'consent' // ensures a refresh_token is always returned
})

console.log('\n1. Open this URL in your browser:\n')
console.log(authUrl)
console.log('\n2. After authorizing, your browser will redirect to http://localhost/?code=...')
console.log('   (The page will fail to load — that is expected)')
console.log('3. Copy the value of "code" from the URL bar and paste it below.\n')

const rl = readline.createInterface({ input: process.stdin, output: process.stdout })

rl.question('Paste the authorization code: ', async (code) => {
  rl.close()
  try {
    const { tokens } = await oauth2Client.getToken(decodeURIComponent(code.trim()))
    if (!tokens.refresh_token) {
      console.error('\nNo refresh_token returned. Try revoking app access at https://myaccount.google.com/permissions and running this script again.')
      process.exit(1)
    }
    console.log('\nAdd these to your .env and Render environment variables:\n')
    console.log(`GOOGLE_REFRESH_TOKEN="${tokens.refresh_token}"`)
    console.log('\nDone. You can delete the service account JSON from GCP — it is no longer needed.')
  } catch (err) {
    console.error('Failed to exchange code for tokens:', err)
    process.exit(1)
  }
})
