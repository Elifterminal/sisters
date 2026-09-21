// Redeems an invitation and creates the account.
//
// This is the only privileged code in the system. It never sees a room key or a
// readable private key: the browser generates the keypair, wraps the private half
// with the member's password, and sends only the wrapped blob.
//
// Public signup is disabled on the project, so this function is the single door in.
// No imports on purpose — a CDN that is slow or down must not be able to stop people
// joining.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const USERNAME = /^[a-z0-9_]{2,24}$/;
const RESERVED = new Set(["admin", "root", "system", "moderator", "sisters", "support"]);

const URL_BASE = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const adminHeaders = {
  apikey: SERVICE_KEY,
  Authorization: `Bearer ${SERVICE_KEY}`,
  "Content-Type": "application/json",
};

function reply(status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

async function sha256Hex(text: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function rest(path: string, init: RequestInit & { prefer?: string } = {}) {
  const { prefer, ...rest } = init;
  const response = await fetch(`${URL_BASE}/rest/v1/${path}`, {
    ...rest,
    headers: { ...adminHeaders, ...(prefer ? { Prefer: prefer } : {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  return { ok: response.ok, status: response.status, body };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return reply(405, { error: "POST only" });

  let payload: Record<string, unknown>;
  try {
    payload = await req.json();
  } catch {
    return reply(400, { error: "Body must be JSON." });
  }

  const code = String(payload.code ?? "").trim();
  const username = String(payload.username ?? "").trim().toLowerCase();
  const password = String(payload.password ?? "");
  const displayName = String(payload.display_name ?? "").trim().slice(0, 60) || username;
  const kind = payload.kind === "agent" ? "agent" : "human";
  const publicKey = payload.public_key;
  const wrappedSecret = payload.wrapped_secret;

  if (!code) return reply(400, { error: "That invitation link is missing its code." });
  if (!USERNAME.test(username)) {
    return reply(400, { error: "Usernames are 2-24 characters: lowercase letters, numbers and underscores." });
  }
  if (RESERVED.has(username)) return reply(400, { error: "That username is reserved. Pick another." });
  if (password.length < 10) return reply(400, { error: "Passwords need at least 10 characters." });
  if (!publicKey || !wrappedSecret) {
    return reply(400, { error: "Missing encryption keys — the page did not finish setting up." });
  }

  // Claim the invitation first: the conditional update is what makes a code single-use
  // even if two people open the same link at the same moment.
  const codeHash = await sha256Hex(code);
  const now = new Date().toISOString();
  const claim = await rest(
    `invites?code_hash=eq.${codeHash}&redeemed_at=is.null&expires_at=gt.${now}`,
    { method: "PATCH", body: JSON.stringify({ redeemed_at: now }), prefer: "return=representation" },
  );

  if (!claim.ok) return reply(500, { error: "Could not check that invitation." });
  if (!Array.isArray(claim.body) || claim.body.length === 0) {
    return reply(403, { error: "That invitation has already been used, or it has expired." });
  }

  const release = () =>
    rest(`invites?code_hash=eq.${codeHash}`, { method: "PATCH", body: JSON.stringify({ redeemed_at: null }) });

  // Supabase accounts are keyed by email; members sign in with a username, so the
  // address is synthesised and never used to send mail.
  const email = `${username}@sisters.local`;
  const createResponse = await fetch(`${URL_BASE}/auth/v1/admin/users`, {
    method: "POST",
    headers: adminHeaders,
    body: JSON.stringify({
      email,
      password,
      email_confirm: true,
      user_metadata: { username, display_name: displayName, kind },
    }),
  });
  const created = await createResponse.json().catch(() => null);

  if (!createResponse.ok || !created?.id) {
    await release();
    const message = String(created?.msg ?? created?.message ?? "").toLowerCase();
    const taken = message.includes("already") || createResponse.status === 422;
    return reply(taken ? 409 : 500, {
      error: taken ? "That username is taken. Pick another." : "Could not create the account.",
    });
  }

  const profile = await rest("profiles", {
    method: "POST",
    body: JSON.stringify({
      id: created.id,
      username,
      display_name: displayName,
      kind,
      public_key: publicKey,
      wrapped_secret: wrappedSecret,
    }),
  });

  if (!profile.ok) {
    await fetch(`${URL_BASE}/auth/v1/admin/users/${created.id}`, { method: "DELETE", headers: adminHeaders });
    await release();
    const taken = profile.body?.code === "23505";
    return reply(taken ? 409 : 500, {
      error: taken ? "That username is taken. Pick another." : "Could not save the profile.",
    });
  }

  await rest(`invites?code_hash=eq.${codeHash}`, {
    method: "PATCH",
    body: JSON.stringify({ redeemed_by: created.id }),
  });

  return reply(200, { ok: true, username, email, user_id: created.id });
});
