import crypto from 'crypto';

// Format: enc:v1:<iv_hex>:<authTag_hex>:<hmac_hex>:<ciphertext_hex>
const ENCRYPTION_PREFIX = 'enc:v1:';
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH = 16; // 128-bit authentication tag

// Derive 32-byte encryption key and 32-byte HMAC integrity key via HKDF
let derivedKeys: { cipherKey: Buffer; hmacKey: Buffer } | null = null;

function getDerivedKeys(): { cipherKey: Buffer; hmacKey: Buffer } {
  if (derivedKeys) return derivedKeys;

  let rawKey = process.env.DB_ENCRYPTION_KEY || '';

  // Fallback for development if not provided in environment
  if (!rawKey || rawKey.trim().length < 16) {
    console.warn('⚠️ [SECURITY NOTICE]: DB_ENCRYPTION_KEY not set or too short. Using system deterministic seed. Set DB_ENCRYPTION_KEY in .env for production.');
    rawKey = 'injectionlab_master_db_encryption_key_sec_v1_2026';
  }

  // Derive keys using HKDF-SHA256
  const masterBuffer = Buffer.from(rawKey, rawKey.length === 64 && /^[0-9a-fA-F]+$/.test(rawKey) ? 'hex' : 'utf-8');
  const salt = Buffer.from('injectionlab_crypto_salt_v1', 'utf-8');
  const info = Buffer.from('injectionlab_db_at_rest_encryption', 'utf-8');

  // Derive 64 bytes total: 32 bytes for AES-256, 32 bytes for HMAC-SHA256
  const derived = crypto.hkdfSync('sha256', masterBuffer, salt, info, 64);
  const derivedBuffer = Buffer.from(derived);

  derivedKeys = {
    cipherKey: derivedBuffer.subarray(0, 32),
    hmacKey: derivedBuffer.subarray(32, 64),
  };

  return derivedKeys;
}

/**
 * Calculates an HMAC-SHA256 over IV + AuthTag + Ciphertext to guarantee data integrity
 */
function calculateHMAC(ivHex: string, authTagHex: string, ciphertextHex: string, hmacKey: Buffer): string {
  const hmac = crypto.createHmac('sha256', hmacKey);
  hmac.update(`${ivHex}:${authTagHex}:${ciphertextHex}`);
  return hmac.digest('hex');
}

/**
 * Encrypts any JS object or string at rest using AES-256-GCM with HMAC integrity validation
 */
export function encryptAtRest(data: any): string {
  if (data === undefined || data === null) return data;

  const { cipherKey, hmacKey } = getDerivedKeys();
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, cipherKey, iv, { authTagLength: AUTH_TAG_LENGTH });

  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  const ivHex = iv.toString('hex');
  const hmacHex = calculateHMAC(ivHex, authTag, ciphertext, hmacKey);

  return `${ENCRYPTION_PREFIX}${ivHex}:${authTag}:${hmacHex}:${ciphertext}`;
}

/**
 * Verifies HMAC integrity and decrypts an encrypted container back to its original object
 */
export function decryptAtRest<T = any>(encryptedString: string): T {
  if (!isEncrypted(encryptedString)) {
    return encryptedString as unknown as T;
  }

  const { cipherKey, hmacKey } = getDerivedKeys();
  const raw = encryptedString.substring(ENCRYPTION_PREFIX.length);
  const parts = raw.split(':');

  if (parts.length !== 4) {
    throw new Error('Cryptographic integrity failure: Malformed encrypted envelope.');
  }

  const [ivHex, authTagHex, hmacHex, ciphertextHex] = parts;

  // 1. Validate HMAC integrity before attempting decryption (prevents tampering)
  const expectedHmac = calculateHMAC(ivHex, authTagHex, ciphertextHex, hmacKey);
  const isHmacValid = crypto.timingSafeEqual(Buffer.from(hmacHex, 'hex'), Buffer.from(expectedHmac, 'hex'));

  if (!isHmacValid) {
    console.error('🚨 [INTEGRITY VIOLATION]: Tamper detected on encrypted database record!');
    throw new Error('Cryptographic integrity failure: Database record has been tampered with or corrupted.');
  }

  // 2. Decrypt with AES-256-GCM
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, cipherKey, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertextHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // 3. Parse JSON if applicable
  try {
    return JSON.parse(decrypted) as T;
  } catch {
    return decrypted as unknown as T;
  }
}

/**
 * Checks if a string is in the encrypted envelope format
 */
export function isEncrypted(value: any): boolean {
  return typeof value === 'string' && value.startsWith(ENCRYPTION_PREFIX);
}

/**
 * Validates HMAC data integrity without decrypting the payload
 */
export function verifyHMACIntegrity(encryptedString: string): boolean {
  if (!isEncrypted(encryptedString)) return false;

  try {
    const { hmacKey } = getDerivedKeys();
    const raw = encryptedString.substring(ENCRYPTION_PREFIX.length);
    const parts = raw.split(':');
    if (parts.length !== 4) return false;

    const [ivHex, authTagHex, hmacHex, ciphertextHex] = parts;
    const expectedHmac = calculateHMAC(ivHex, authTagHex, ciphertextHex, hmacKey);
    return crypto.timingSafeEqual(Buffer.from(hmacHex, 'hex'), Buffer.from(expectedHmac, 'hex'));
  } catch {
    return false;
  }
}

/**
 * Utility for recursively encrypting sensitive properties of an object
 */
export function encryptSensitiveFields<T extends Record<string, any>>(obj: T, fieldsToEncrypt: Array<keyof T>): T {
  const result: any = { ...obj };
  for (const field of fieldsToEncrypt) {
    if (result[field] !== undefined && result[field] !== null) {
      result[field] = encryptAtRest(result[field]);
    }
  }
  return result;
}

/**
 * Utility for recursively decrypting sensitive properties of an object
 */
export function decryptSensitiveFields<T extends Record<string, any>>(obj: T, fieldsToDecrypt: Array<keyof T>): T {
  const result: any = { ...obj };
  for (const field of fieldsToDecrypt) {
    if (isEncrypted(result[field])) {
      try {
        result[field] = decryptAtRest(result[field]);
      } catch (err: any) {
        console.error(`Failed to decrypt field "${String(field)}":`, err.message);
      }
    }
  }
  return result;
}
