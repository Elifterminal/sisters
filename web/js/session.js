// Holds the keys for the signed-in member and keeps room keys flowing to new members.

import { auth, db, signIn as apiSignIn, callFunction } from "./api.js";
import {
  generateMemberKeys,
  wrapPrivateKey,
  unwrapPrivateKey,
  exportPublicKey,
  generateRoomKey,
  wrapRoomKey,
  unwrapRoomKey,
  sha256Hex,
  b64,
} from "./crypto.js";

// The unwrapped private key lives here, and in sessionStorage so a page refresh
// does not demand the password again. It never goes to the server, and the tab
// closing takes it with it.
const CACHE_KEY = "sisters.secret";

const state = {
  profile: null,
  privateKey: null,
  roomKeys: new Map(), // `${roomId}:${epoch}` -> Uint8Array
  members: [],
};

export const me = () => state.profile;
export const myPrivateKey = () => state.privateKey;
export const members = () => state.members;

function cacheSecret(pkcs8) {
  try {
    sessionStorage.setItem(CACHE_KEY, b64.from(pkcs8));
  } catch {
    /* nothing cached: the member re-enters their password after a refresh */
  }
}

async function restoreSecret() {
  let stored = null;
  try {
    stored = sessionStorage.getItem(CACHE_KEY);
  } catch {
    return null;
  }
  if (!stored) return null;
  return crypto.subtle.importKey("pkcs8", b64.to(stored), { name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
}

export function clear() {
  state.profile = null;
  state.privateKey = null;
  state.roomKeys.clear();
  state.members = [];
  auth.signOut();
  try {
    sessionStorage.removeItem(CACHE_KEY);
  } catch {
    /* ignore */
  }
}

/** Signs in and unlocks the member's private key with the same password. */
export async function signIn(username, password) {
  await apiSignIn(username, password);
  const profile = await db.me();
  if (!profile) {
    clear();
    throw new Error("That account has no profile. Ask whoever invited you to check it.");
  }
  try {
    state.privateKey = await unwrapPrivateKey(profile.wrapped_secret, password);
  } catch (error) {
    clear();
    throw new Error(
      error.message === "WRONG_PASSWORD"
        ? "Signed in, but that password did not unlock your keys. If you changed it, your old messages need the old password."
        : "Could not unlock your keys.",
    );
  }
  cacheSecret(await crypto.subtle.exportKey("pkcs8", state.privateKey));
  state.profile = profile;
  state.members = await db.members();
  return profile;
}

/** Restores a session after a refresh, without asking for the password again. */
export async function resume() {
  if (!auth.signedIn()) return null;
  const privateKey = await restoreSecret();
  if (!privateKey) return null;
  const profile = await db.me().catch(() => null);
  if (!profile) return null;
  state.privateKey = privateKey;
  state.profile = profile;
  state.members = await db.members().catch(() => []);
  return profile;
}

/** Creates the account behind an invitation. All key material is made here, in the browser. */
export async function redeemInvite({ code, username, password, displayName, kind }) {
  const pair = await generateMemberKeys();
  const payload = {
    code,
    username,
    password,
    display_name: displayName,
    kind,
    public_key: await exportPublicKey(pair.publicKey),
    wrapped_secret: await wrapPrivateKey(pair.privateKey, password),
  };
  await callFunction("join", payload);
  return signIn(username, password);
}

// ---------------------------------------------------------------- room keys

export async function loadRoomKeys() {
  if (!state.privateKey) return;
  const rows = await db.myRoomKeys();
  for (const row of rows) {
    const id = `${row.room_id}:${row.epoch}`;
    if (state.roomKeys.has(id)) continue;
    try {
      state.roomKeys.set(id, await unwrapRoomKey(row.wrapped, state.privateKey));
    } catch {
      /* A key we cannot open: rotated away, or wrapped for a different keypair. */
    }
  }
}

export function roomKey(room) {
  return state.roomKeys.get(`${room.id}:${room.epoch}`) ?? null;
}

export function canRead(room) {
  return Boolean(roomKey(room));
}

/** Makes a room and hands its key to every current member, including the creator. */
export async function createRoom({ slug, name, description }) {
  const room = await db.createRoom({ slug, name, description, created_by: state.profile.id, epoch: 1 });
  const key = await generateRoomKey();
  state.roomKeys.set(`${room.id}:${room.epoch}`, key);
  state.members = await db.members();
  await shareKey(room, key, state.members);
  return room;
}

async function shareKey(room, key, recipients) {
  const rows = [];
  for (const member of recipients) {
    rows.push({
      room_id: room.id,
      member_id: member.id,
      epoch: room.epoch,
      wrapped: await wrapRoomKey(key, member.public_key),
      wrapped_by: state.profile.id,
    });
  }
  if (rows.length) await db.shareRoomKey(rows);
}

/** True when nobody alive holds this room's current key, so it can never be read. */
export async function isOrphaned(room) {
  if (roomKey(room)) return false;
  const holders = await db.roomKeyHolders(room.id, room.epoch);
  return holders.length === 0;
}

/**
 * Gives an unreadable room a fresh key under a new epoch and shares it with everyone.
 * Posts written under the old key stay unreadable — they already were, to everybody.
 */
export async function rekeyRoom(room) {
  const key = await generateRoomKey();
  const epoch = room.epoch + 1;
  await db.setRoomEpoch(room.id, epoch);
  const next = { ...room, epoch };
  state.roomKeys.set(`${next.id}:${epoch}`, key);
  state.members = await db.members();
  await shareKey(next, key, state.members);
  return next;
}

/**
 * Hands room keys to members who joined after the room was made.
 * Anybody who can already read a room can do this, so a new member does not have
 * to wait for one particular person to be online.
 */
export async function shareKeysWithNewMembers(rooms) {
  if (!state.profile) return 0;
  state.members = await db.members();
  let shared = 0;

  for (const room of rooms) {
    const key = roomKey(room);
    if (!key) continue;
    const holders = await db.roomKeyHolders(room.id, room.epoch);
    const have = new Set(holders.map((row) => row.member_id));
    const missing = state.members.filter((member) => !have.has(member.id));
    if (!missing.length) continue;
    await shareKey(room, key, missing);
    shared += missing.length;
  }
  return shared;
}

// ---------------------------------------------------------------- invitations

/** Returns the link to hand over. Only its hash is stored, so this is the one copy. */
export async function createInvite(label) {
  const { newInviteCode } = await import("./crypto.js");
  const code = newInviteCode();
  await db.createInvite({
    code_hash: await sha256Hex(code),
    label: label || null,
    created_by: state.profile.id,
  });
  const base = location.href.split("#")[0];
  return { code, url: `${base}#/join?code=${encodeURIComponent(code)}` };
}
