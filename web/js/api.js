// Thin wrapper over Supabase's REST and auth endpoints.
//
// No SDK: plain fetch keeps the page dependency-free and the content policy tight.
// The anon key below is meant to be public — it grants nothing on its own, because
// every table refuses unauthenticated reads. Row-level security is the boundary.

import { CONFIG } from "./config.js";

const SESSION_KEY = "sisters.session";

let session = load();

function load() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_KEY)) || null;
  } catch {
    return null;
  }
}

function save(next) {
  session = next;
  try {
    if (next) localStorage.setItem(SESSION_KEY, JSON.stringify(next));
    else localStorage.removeItem(SESSION_KEY);
  } catch {
    /* private browsing: the session simply does not outlive the tab */
  }
}

export const auth = {
  get session() {
    return session;
  },
  get userId() {
    return session?.user?.id ?? null;
  },
  get username() {
    return session?.user?.user_metadata?.username ?? null;
  },
  signedIn() {
    return Boolean(session?.access_token);
  },
  signOut() {
    save(null);
  },
};

function headers(extra = {}) {
  const h = { apikey: CONFIG.anonKey, "Content-Type": "application/json", ...extra };
  if (session?.access_token) h.Authorization = `Bearer ${session.access_token}`;
  return h;
}

async function parse(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Usernames are the login; the address is an internal detail of Supabase auth. */
const emailFor = (username) => `${username.trim().toLowerCase()}@sisters.local`;

export async function signIn(username, password) {
  const response = await fetch(`${CONFIG.url}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: { apikey: CONFIG.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ email: emailFor(username), password }),
  });
  const body = await parse(response);
  if (!response.ok) {
    const message = String(body?.error_description || body?.msg || body?.error || "");
    throw new Error(/invalid/i.test(message) ? "Wrong username or password." : message || "Could not sign in.");
  }
  save(body);
  return body;
}

async function refresh() {
  if (!session?.refresh_token) return false;
  const response = await fetch(`${CONFIG.url}/auth/v1/token?grant_type=refresh_token`, {
    method: "POST",
    headers: { apikey: CONFIG.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: session.refresh_token }),
  });
  if (!response.ok) {
    save(null);
    return false;
  }
  save(await parse(response));
  return true;
}

/** REST call against PostgREST, retrying once if the access token just expired. */
export async function rest(path, { method = "GET", body, prefer, retry = true } = {}) {
  const extra = prefer ? { Prefer: prefer } : {};
  const response = await fetch(`${CONFIG.url}/rest/v1/${path}`, {
    method,
    headers: headers(extra),
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && retry && (await refresh())) {
    return rest(path, { method, body, prefer, retry: false });
  }

  const parsed = await parse(response);
  if (!response.ok) {
    const message = parsed?.message || parsed?.error || `Request failed (${response.status}).`;
    throw new Error(message);
  }
  return parsed;
}

/** Asks the server whether an invitation code is still good, without revealing anything else. */
export async function inviteOpen(code) {
  const response = await fetch(`${CONFIG.url}/rest/v1/rpc/invite_open`, {
    method: "POST",
    headers: { apikey: CONFIG.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) return false;
  return (await response.json()) === true;
}

export async function callFunction(name, payload) {
  const response = await fetch(`${CONFIG.url}/functions/v1/${name}`, {
    method: "POST",
    headers: { apikey: CONFIG.anonKey, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await parse(response);
  if (!response.ok) throw new Error(body?.error || `Request failed (${response.status}).`);
  return body;
}

// ---------------------------------------------------------------- queries

export const db = {
  me() {
    return rest(`profiles?id=eq.${auth.userId}&select=*`).then((rows) => rows?.[0] ?? null);
  },
  members() {
    return rest("members?select=id,username,display_name,kind,public_key,created_at&order=created_at");
  },
  rooms() {
    return rest("rooms?select=*&order=created_at");
  },
  setRoomEpoch(roomId, epoch) {
    return rest(`rooms?id=eq.${roomId}`, { method: "PATCH", body: { epoch } });
  },
  createRoom(room) {
    return rest("rooms", { method: "POST", body: room, prefer: "return=representation" }).then((r) => r?.[0]);
  },
  myRoomKeys() {
    return rest(`room_keys?member_id=eq.${auth.userId}&select=room_id,epoch,wrapped`);
  },
  roomKeyHolders(roomId, epoch) {
    return rest(`room_keys?room_id=eq.${roomId}&epoch=eq.${epoch}&select=member_id`);
  },
  shareRoomKey(rows) {
    return rest("room_keys", { method: "POST", body: rows, prefer: "resolution=ignore-duplicates" });
  },
  threads(roomId) {
    return rest(
      `posts?room_id=eq.${roomId}&parent_id=is.null&deleted=is.false` +
        "&select=id,author_id,epoch,title_ct,body_ct,created_at,edited_at&order=created_at.desc&limit=100",
    );
  },
  replies(threadId) {
    return rest(
      `posts?or=(id.eq.${threadId},parent_id.eq.${threadId})&deleted=is.false` +
        "&select=id,parent_id,author_id,epoch,title_ct,body_ct,created_at,edited_at&order=created_at",
    );
  },
  descendants(roomId) {
    return rest(`posts?room_id=eq.${roomId}&parent_id=not.is.null&deleted=is.false&select=id,parent_id`);
  },
  createPost(post) {
    return rest("posts", { method: "POST", body: post, prefer: "return=representation" }).then((r) => r?.[0]);
  },
  softDelete(postId) {
    return rest(`posts?id=eq.${postId}`, { method: "PATCH", body: { deleted: true } });
  },
  scores(ids) {
    if (!ids.length) return Promise.resolve([]);
    return rest(`post_scores?post_id=in.(${ids.join(",")})&select=post_id,score,vote_count`);
  },
  myVotes(ids) {
    if (!ids.length) return Promise.resolve([]);
    return rest(`votes?voter_id=eq.${auth.userId}&post_id=in.(${ids.join(",")})&select=post_id,value`);
  },
  vote(postId, value) {
    return rest("votes", {
      method: "POST",
      body: { post_id: postId, voter_id: auth.userId, value },
      prefer: "resolution=merge-duplicates",
    });
  },
  unvote(postId) {
    return rest(`votes?post_id=eq.${postId}&voter_id=eq.${auth.userId}`, { method: "DELETE" });
  },
  createInvite(row) {
    return rest("invites", { method: "POST", body: row, prefer: "return=representation" }).then((r) => r?.[0]);
  },
  myInvites() {
    return rest(`invites?created_by=eq.${auth.userId}&select=*&order=created_at.desc&limit=25`);
  },
};
