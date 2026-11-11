import 'fastify'

interface LegacyCredentialBody {
  formatVersion?: 1
  siteName: string
  usernameHint?: string
  url?: string
  encryptedPayload: string
  iv: string
}

interface EncryptedCredentialBody {
  formatVersion: 2
  encryptedPayload: string
  iv: string
}

export type CredentialBody = LegacyCredentialBody | EncryptedCredentialBody

export interface CredentialParams {
  id: string
}

export interface VaultConfigBody {
  masterSalt: string
  encryptedVaultKey: string
  vaultKeyIv: string
}

export interface UpdateVaultConfigBody extends VaultConfigBody {
  revision: number
}

export interface CreateUserBody {
  username: string
}

export interface UserParams {
  id: string
}

// Augment FastifyRequest so route handlers can read req.userId after auth.
declare module 'fastify' {
  interface FastifyRequest {
    userId: string
  }

  interface FastifyContextConfig {
    allowDeviceRead?: boolean
  }
}
