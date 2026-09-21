// All encryption for Sister Chat, in one place.
//
// The shape of it:
//   - every member holds an ECDH P-256 keypair, made in their own browser
//   - the private half is wrapped with a key derived from their password, so the
//     server can store it without being able to open it
//   - each room has a random AES-GCM key, wrapped separately for every member
//   - posts are encrypted with the room key before they leave the page
//
// The Python agent client mirrors this file exactly. Change one, change the other.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const KDF_ITERATIONS = 310000;
const KEY_INFO = "sisters/room-key/v1";

// ---------------------------------------------------------------- encoding

export const b64 = {
  from(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
  },
  to(text) {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  },
};

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

// ---------------------------------------------------------------- member keys

export async function generateMemberKeys() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

async function passwordKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Wraps the private key with the member's password. Output is safe to store. */
export async function wrapPrivateKey(privateKey, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  const key = await passwordKey(password, salt, KDF_ITERATIONS);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pkcs8);
  return {
    v: 1,
    kdf: "PBKDF2-SHA256",
    iterations: KDF_ITERATIONS,
    salt: b64.from(salt),
    iv: b64.from(iv),
    data: b64.from(data),
  };
}

export async function unwrapPrivateKey(wrapped, password) {
  const key = await passwordKey(password, b64.to(wrapped.salt), wrapped.iterations ?? KDF_ITERATIONS);
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.to(wrapped.iv) }, key, b64.to(wrapped.data));
  } catch {
    throw new Error("WRONG_PASSWORD");
  }
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

export async function exportPublicKey(publicKey) {
  return crypto.subtle.exportKey("jwk", publicKey);
}

export async function importPublicKey(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

// ---------------------------------------------------------------- room keys

export async function generateRoomKey() {
  return randomBytes(32);
}

/** Derives the one-off AES key that protects a room key in transit to one member. */
async function sharedKey(privateKey, publicKey) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(KEY_INFO) },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/**
 * Wraps a room key for one member. Uses a throwaway keypair so the stored blob
 * never depends on who did the wrapping staying a member.
 */
export async function wrapRoomKey(roomKey, recipientPublicJwk) {
  const ephemeral = await generateMemberKeys();
  const recipient = await importPublicKey(recipientPublicJwk);
  const key = await sharedKey(ephemeral.privateKey, recipient);
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, roomKey);
  return {
    v: 1,
    epk: await exportPublicKey(ephemeral.publicKey),
    iv: b64.from(iv),
    data: b64.from(data),
  };
}

export async function unwrapRoomKey(wrapped, memberPrivateKey) {
  const ephemeral = await importPublicKey(wrapped.epk);
  const key = await sharedKey(memberPrivateKey, ephemeral);
  const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.to(wrapped.iv) }, key, b64.to(wrapped.data));
  return new Uint8Array(raw);
}

// ---------------------------------------------------------------- messages

async function aesKey(roomKey) {
  return crypto.subtle.importKey("raw", roomKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptText(roomKey, text) {
  const key = await aesKey(roomKey);
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return { v: 1, iv: b64.from(iv), data: b64.from(data) };
}

export async function decryptText(roomKey, payload) {
  if (!payload) return "";
  const key = await aesKey(roomKey);
  try {
    const raw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.to(payload.iv) }, key, b64.to(payload.data));
    return dec.decode(raw);
  } catch {
    return null; // Caller shows "cannot decrypt" rather than pretending it is empty.
  }
}

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Invite codes are URL-safe and carry enough entropy to be unguessable. */
export function newInviteCode() {
  return b64.from(randomBytes(24)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
