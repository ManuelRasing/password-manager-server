import type { Prisma } from '@prisma/client'
import prisma from './prisma'

export async function withCredentialWrite<T>(
  userId: string,
  operation: (tx: Prisma.TransactionClient, minimumFormat: number) => Promise<T>
): Promise<T> {
  return prisma.$transaction(async (tx) => {
    const owner = await tx.$queryRaw<Array<{ id: string }>>`SELECT id FROM "User" WHERE id = ${userId} FOR SHARE`
    if (owner.length !== 1) throw new Error('Vault owner is unavailable')
    const config = await tx.vaultConfig.findUnique({
      where: { userId }, select: { minCredentialFormat: true }
    })
    return operation(tx, config?.minCredentialFormat ?? 1)
  })
}

export const credentialSelect = {
  id: true,
  formatVersion: true,
  siteName: true,
  usernameHint: true,
  url: true,
  encryptedPayload: true,
  iv: true,
  createdAt: true,
  updatedAt: true
} as const

type SelectedCredential = Prisma.CredentialGetPayload<{ select: typeof credentialSelect }>

export function serializeCredential({
  formatVersion, siteName, usernameHint, url, ...credential
}: SelectedCredential) {
  if (formatVersion === 1) {
    return { ...credential, siteName, usernameHint, url }
  }
  return { ...credential, formatVersion }
}
