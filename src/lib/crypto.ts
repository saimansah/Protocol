/**
 * Protocol 594 // Web Crypto API End-to-End Encryption (E2EE) Module
 * Zero-knowledge client-side AES-256-GCM encryption with PBKDF2 key derivation.
 * Guarantees zero plaintext exposure across Supabase Realtime WebSocket relays.
 */

// Helper to safely obtain the Web Crypto SubtleCrypto instance
function getSubtleCrypto(): SubtleCrypto {
  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error('Web Crypto API (crypto.subtle) is not supported in this environment.');
}

/**
 * Derives an AES-GCM 256-bit CryptoKey from a user password and room salt using PBKDF2.
 */
export async function deriveRoomKey(password: string, saltString: string): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();

  // Import raw password as key material for PBKDF2
  const keyMaterial = await subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  // Use a domain-separated salt incorporating the unique room ID
  const salt = encoder.encode(`protocol_594_cipher_salt:${saltString}`);

  // Derive an AES-256-GCM key with 100,000 iterations of SHA-256
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts plaintext using AES-256-GCM with a freshly generated 12-byte IV.
 */
export async function encryptPayload(
  plaintext: string,
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();

  // Fresh 12-byte initialization vector per message
  const iv = new Uint8Array(12);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(iv);
  } else if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    globalThis.crypto.getRandomValues(iv);
  } else {
    throw new Error('crypto.getRandomValues is unavailable.');
  }

  const encodedText = encoder.encode(plaintext);
  const encryptedBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
    },
    key,
    encodedText as unknown as BufferSource
  );

  return {
    ciphertext: bufferToBase64(new Uint8Array(encryptedBuffer)),
    iv: bufferToBase64(iv),
  };
}

/**
 * Decrypts an AES-256-GCM encrypted payload using the derived CryptoKey.
 */
export async function decryptPayload(
  ciphertextBase64: string,
  ivBase64: string,
  key: CryptoKey
): Promise<string> {
  const subtle = getSubtleCrypto();
  const decoder = new TextDecoder();

  const iv = base64ToBuffer(ivBase64);
  const encryptedBytes = base64ToBuffer(ciphertextBase64);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
    },
    key,
    encryptedBytes as unknown as BufferSource
  );

  return decoder.decode(decryptedBuffer);
}

// Base64 conversion utilities
function bufferToBase64(buffer: Uint8Array): string {
  let binary = '';
  const len = buffer.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }
  return typeof btoa === 'function' ? btoa(binary) : Buffer.from(buffer).toString('base64');
}

function base64ToBuffer(base64: string): Uint8Array {
  if (typeof atob === 'function') {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  return new Uint8Array(Buffer.from(base64, 'base64'));
}
