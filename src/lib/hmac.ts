import crypto from 'crypto'

const TIMESTAMP_TOLERANCE_MS = 30_000

/**
 * Signed message format: METHOD|PATH|TIMESTAMP|BODY_SHA256
 * The raw API key is never transmitted — only the HMAC signature.
 */
export function computeHmac(
  secret: string,
  method: string,
  path: string,
  timestamp: string,
  bodyHash: string
): string {
  const message = [method.toUpperCase(), path, timestamp, bodyHash].join('|')
  return crypto.createHmac('sha256', secret).update(message).digest('hex')
}

export function hashBody(body: unknown): string {
  const str = body ? JSON.stringify(body) : ''
  return crypto.createHash('sha256').update(str).digest('hex')
}

export function isTimestampValid(timestamp: string): boolean {
  const tsMs = parseInt(timestamp, 10) * 1000
  if (isNaN(tsMs)) return false
  return Math.abs(Date.now() - tsMs) <= TIMESTAMP_TOLERANCE_MS
}

// Constant-time comparison — prevents timing attacks on the signature
export function safeEqual(a: string, b: string): boolean {
  try {
    const aBuf = Buffer.from(a, 'hex')
    const bBuf = Buffer.from(b, 'hex')
    if (aBuf.length !== bBuf.length) return false
    return crypto.timingSafeEqual(aBuf, bBuf)
  } catch {
    return false
  }
}
