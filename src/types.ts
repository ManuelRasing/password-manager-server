import 'fastify'

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
}
