import crypto from 'crypto';

interface TransitSession {
  sessionId: string;
  keyHex: string;
  createdAt: number;
  expiresAt: number;
}

const activeTransitSessions = new Map<string, TransitSession>();
const SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

/**
 * Creates or refreshes an ephemeral AES-256-GCM session key for client-server payload encryption
 */
export function createTransitSession(customSessionId?: string): { sessionId: string; sessionKeyHex: string; expiresAt: string } {
  const sessionId = customSessionId || 'transit_' + crypto.randomBytes(16).toString('hex');
  const sessionKey = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  const expiresAt = now + SESSION_TTL_MS;

  activeTransitSessions.set(sessionId, {
    sessionId,
    keyHex: sessionKey,
    createdAt: now,
    expiresAt,
  });

  // Clean up expired sessions
  for (const [id, session] of activeTransitSessions.entries()) {
    if (session.expiresAt < now) {
      activeTransitSessions.delete(id);
    }
  }

  return {
    sessionId,
    sessionKeyHex: sessionKey,
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

/**
 * Gets the active key for a transit session
 */
export function getTransitSessionKey(sessionId: string): string | null {
  const session = activeTransitSessions.get(sessionId);
  if (!session) return null;
  if (session.expiresAt < Date.now()) {
    activeTransitSessions.delete(sessionId);
    return null;
  }
  return session.keyHex;
}

/**
 * Encrypts data for transit back to client
 */
export function encryptTransitPayload(data: any, sessionKeyHex: string): { iv: string; authTag: string; ciphertext: string } {
  const key = Buffer.from(sessionKeyHex, 'hex');
  const iv = crypto.randomBytes(IV_LENGTH);
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    iv: iv.toString('hex'),
    authTag,
    ciphertext,
  };
}

/**
 * Decrypts data received from client in transit
 */
export function decryptTransitPayload<T = any>(
  envelope: { iv: string; authTag: string; ciphertext: string },
  sessionKeyHex: string
): T {
  const key = Buffer.from(sessionKeyHex, 'hex');
  const iv = Buffer.from(envelope.iv, 'hex');
  const authTag = Buffer.from(envelope.authTag, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(envelope.ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  try {
    return JSON.parse(decrypted) as T;
  } catch {
    return decrypted as unknown as T;
  }
}
