import { api } from './api';

let currentSessionId: string | null = null;
let currentSessionKeyHex: string | null = null;
let currentCryptoKey: CryptoKey | null = null;

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Initializes or retrieves an active AES-256-GCM in-transit payload encryption session
 */
export async function getTransitSession(): Promise<{ sessionId: string; key: CryptoKey }> {
  if (currentSessionId && currentCryptoKey) {
    return { sessionId: currentSessionId, key: currentCryptoKey };
  }

  const res = await api.post('/security/handshake');
  const { sessionId, sessionKey } = res.data;

  const keyBytes = hexToBytes(sessionKey);
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyBytes as ArrayBufferView<ArrayBuffer>,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );

  currentSessionId = sessionId;
  currentSessionKeyHex = sessionKey;
  currentCryptoKey = cryptoKey;

  return { sessionId, key: cryptoKey };
}

/**
 * Encrypts client payload using AES-256-GCM before sending over the wire
 */
export async function encryptTransitPayload(data: any): Promise<{
  sessionId: string;
  envelope: { iv: string; authTag: string; ciphertext: string };
}> {
  const { sessionId, key } = await getTransitSession();
  const plaintext = typeof data === 'string' ? data : JSON.stringify(data);
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);

  // 12-byte IV for AES-GCM
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  // Web Crypto AES-GCM appends 16-byte auth tag at the end of the ciphertext
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: 128 },
    key,
    plaintextBytes
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertextBytes = encryptedBytes.subarray(0, encryptedBytes.length - 16);
  const authTagBytes = encryptedBytes.subarray(encryptedBytes.length - 16);

  return {
    sessionId,
    envelope: {
      iv: bytesToHex(iv),
      authTag: bytesToHex(authTagBytes),
      ciphertext: bytesToHex(ciphertextBytes),
    },
  };
}

/**
 * Decrypts server response envelope using the active AES-256-GCM session key
 */
export async function decryptTransitResponse<T = any>(envelope: {
  iv: string;
  authTag: string;
  ciphertext: string;
}): Promise<T> {
  const { key } = await getTransitSession();

  const iv = hexToBytes(envelope.iv);
  const authTag = hexToBytes(envelope.authTag);
  const ciphertext = hexToBytes(envelope.ciphertext);

  // Combine ciphertext + auth tag for Web Crypto SubtleCrypto
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as ArrayBufferView<ArrayBuffer>, tagLength: 128 },
    key,
    combined as ArrayBufferView<ArrayBuffer>
  );

  const decoder = new TextDecoder();
  const decryptedText = decoder.decode(decryptedBuffer);

  try {
    return JSON.parse(decryptedText) as T;
  } catch {
    return decryptedText as unknown as T;
  }
}
