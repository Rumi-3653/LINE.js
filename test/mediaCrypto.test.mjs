import test from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { decryptLineMedia, installLineMediaDecrypt } from "../dist/line/mediaCrypto.js";

// Encrypts as the LINE Encryption Overview v2.2 describes: AES-256-CTR, then either one MAC over the
// ciphertext (image/audio/file) or one MAC over the SHA-256 of every 128 KB ciphertext chunk (video).
function encrypt(payload, keyMaterial, video) {
  const derived = Buffer.from(hkdfSync("sha256", keyMaterial, Buffer.alloc(0), "FileEncryption", 76));
  const cipher = createCipheriv("aes-256-ctr", derived.subarray(0, 32), Buffer.concat([derived.subarray(64, 76), Buffer.alloc(4)]));
  const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
  const mac = createHmac("sha256", derived.subarray(32, 64));
  if (video) for (let offset = 0; offset < ciphertext.length; offset += 128 * 1024) mac.update(createHash("sha256").update(ciphertext.subarray(offset, offset + 128 * 1024)).digest());
  else mac.update(ciphertext);
  return Buffer.concat([ciphertext, mac.digest()]);
}

test("an image with a whole-file MAC decrypts", () => {
  const keyMaterial = randomBytes(32);
  const payload = randomBytes(5000);
  assert.deepEqual(decryptLineMedia(encrypt(payload, keyMaterial, false), keyMaterial), payload);
});

test("a video authenticated over its 128 KB chunk hashes decrypts", () => {
  const keyMaterial = randomBytes(32);
  const payload = randomBytes(300 * 1024 + 17);
  assert.deepEqual(decryptLineMedia(encrypt(payload, keyMaterial, true), keyMaterial.toString("base64")), payload);
});

test("a wrong key or a tampered file is refused before decrypting", () => {
  const keyMaterial = randomBytes(32);
  const video = encrypt(randomBytes(200 * 1024), keyMaterial, true);
  assert.throws(() => decryptLineMedia(video, randomBytes(32)), /E2EE_MEDIA_MAC_MISMATCH/);
  video[1000] ^= 1;
  assert.throws(() => decryptLineMedia(video, keyMaterial), /E2EE_MEDIA_MAC_MISMATCH/);
  assert.throws(() => decryptLineMedia(Buffer.alloc(10), keyMaterial), /E2EE_MEDIA_TOO_SHORT/);
});

test("the installed decrypt replaces the library's whole-file-only check", async () => {
  const base = { e2ee: { decryptByKeyMaterial: async () => { throw new Error("HMAC verification failed"); } } };
  installLineMediaDecrypt(base);
  const keyMaterial = randomBytes(32);
  const payload = randomBytes(150 * 1024);
  assert.deepEqual(await base.e2ee.decryptByKeyMaterial(encrypt(payload, keyMaterial, true), keyMaterial.toString("base64")), payload);
});
