/**
 * AES-256-CBC encryption helpers using the Web Crypto API.
 *
 * All operations are async; the key should be derived once in LTIKit.setup() and reused throughout
 * the lifecycle.
 */

const ENC = new TextEncoder();
const DEC = new TextDecoder();

/**
 * Derive a 256-bit AES-CBC CryptoKey from an arbitrary string passphrase
 * by SHA-256 hashing it.
 */
export async function deriveAesKey(passphrase: string): Promise<CryptoKey> {
  const hash = await crypto.subtle.digest("SHA-256", ENC.encode(passphrase));
  return crypto.subtle.importKey("raw", hash, { name: "AES-CBC" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt a UTF-8 string. Returns `<iv_hex>:<ciphertext_hex>`. */
export async function encrypt(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    ENC.encode(plaintext),
  );
  return `${new Uint8Array(iv).toHex()}:${new Uint8Array(cipherBuf).toHex()}`;
}

/** Decrypt a value produced by `encrypt`. */
export async function decrypt(ciphertext: string, key: CryptoKey): Promise<string> {
  const [ivHex, datHex] = ciphertext.split(":");
  const iv = Uint8Array.fromHex(ivHex);
  const data = Uint8Array.fromHex(datHex);
  const plain = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, data);
  return DEC.decode(plain);
}

export async function hash(plaintext: string) {

    const bytes: ArrayBuffer = await crypto.subtle.digest("SHA-256", (new TextEncoder()).encode(plaintext));
    return new Uint8Array(bytes).toHex();
}
