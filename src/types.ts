export interface CredentialBody {
  siteName: string
  usernameHint?: string
  encryptedPayload: string
  iv: string
}

export interface CredentialParams {
  id: string
}
