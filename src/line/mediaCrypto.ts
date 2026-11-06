import { createDecipheriv, createHash, createHmac, hkdfSync, timingSafeEqual } from "node:crypto";

/** LINE authenticates video differently from other media (LINE Encryption Overview v2.2, "Video Encryption"). */
const VIDEO_CHUNK_BYTES = 128 * 1024;
const MAC_BYTES = 32;

/**
 * Decrypts a Letter Sealing media file: ciphertext followed by a 32-byte HMAC-SHA256 tag. Images,
 * audio and files MAC the ciphertext itself; video MACs the concatenated SHA-256 of each 128 KB
 * ciphertext chunk. Either MAC must verify before anything is decrypted (fail closed).
 */
export function decryptLineMedia(raw: Buffer, keyMaterial: Buffer | string): Buffer {
  if (raw.length < MAC_BYTES) throw new Error("E2EE_MEDIA_TOO_SHORT");
  const key = typeof keyMaterial === "string" ? Buffer.from(keyMaterial, "base64") : keyMaterial;
  const derived = Buffer.from(hkdfSync("sha256", key, Buffer.alloc(0), "FileEncryption", 76));
  const encKey = derived.subarray(0, 32);
  const macKey = derived.subarray(32, 64);
  const ciphertext = raw.subarray(0, -MAC_BYTES);
  const tag = raw.subarray(-MAC_BYTES);
  const whole = createHmac("sha256", macKey).update(ciphertext).digest();
  if (!timingSafeEqual(whole, tag)) {
    const chunked = createHmac("sha256", macKey);
    for (let offset = 0; offset < ciphertext.length; offset += VIDEO_CHUNK_BYTES) {
      chunked.update(createHash("sha256").update(ciphertext.subarray(offset, offset + VIDEO_CHUNK_BYTES)).digest());
    }
    if (!timingSafeEqual(chunked.digest(), tag)) throw new Error("E2EE_MEDIA_MAC_MISMATCH");
  }
  // The 12-byte IV is extended with a 32-bit block counter starting at zero.
  const decipher = createDecipheriv("aes-256-ctr", encKey, Buffer.concat([derived.subarray(64, 76), Buffer.alloc(4)]));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * LINEJS 3.4.2's `downloadMediaByE2EE` verifies every file as a whole-file MAC, so every encrypted
 * video fails. Its decrypt step is swapped for one that also knows the video layout.
 */
export function installLineMediaDecrypt(base: { e2ee: { decryptByKeyMaterial: unknown } }): void {
  base.e2ee.decryptByKeyMaterial = async (raw: Buffer, keyMaterial: Buffer | string) => decryptLineMedia(raw, keyMaterial);
}
