export interface CredentialBody {
  siteName: string
  usernameHint?: string
  url?: string
  encryptedPayload: string
  iv: string
}

export interface CredentialParams {
  id: string
}

export interface VaultConfigBody {
  masterSalt: string
  encryptedVaultKey: string
  vaultKeyIv: string
}
