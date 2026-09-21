// Sister Chat — the page.
//
// Everything shown here was decrypted a moment ago in this tab. Anything that
// leaves goes out as ciphertext.

import { auth, db } from "./api.js";
import { encryptText, decryptText } from "./crypto.js";
import * as session from "./session.js";

const $ = (sel, root = document) => root.querySelector(sel);
const view = $("#view");
const nav = $("#nav");

const state = { rooms: [], room: null, membersById: new Map() };

// ---------------------------------------------------------------- utilities

function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

function ago(iso) {
  const seconds = Math.max(1, (Date.now() - new Date(iso)) / 1000);
  const steps = [[60, "second"], [60, "minute"], [24, "hour"], [7, "day"], [4.35, "week"], [12, "month"]];
  let value = seconds;
  let unit = "second";
  for (const [size, name] of steps) {
    if (value < size) break;
    value /= size;
    unit = name === "second" ? "minute" : name === "minute" ? "hour" : name === "hour" ? "day" : name === "day" ? "week" : name === "week" ? "month" : "year";
  }
  const rounded = Math.floor(value);
  return `${rounded} ${unit}${rounded === 1 ? "" : "s"} ago`;
}

const authorName = (id) => state.membersById.get(id)?.username ?? "someone";

function notice(message, kind = "info") {
  const bar = $("#notice");
  bar.textContent = message;
  bar.className = message ? `notice ${kind}` : "notice";
}

function busy(on) {
  document.body.classList.toggle("busy", Boolean(on));
}

// ---------------------------------------------------------------- chrome

function renderNav() {
  nav.replaceChildren();
  if (!session.me()) return;

  const rooms = el("div", { className: "rooms" },
    state.rooms.map((room) =>
      el("a", {
        href: `#/r/${room.slug}`,
        className: `room-link${state.room?.id === room.id ? " current" : ""}${session.canRead(room) ? "" : " locked"}`,
        title: session.canRead(room) ? room.description || room.name : "You do not hold this room's key yet.",
      }, room.name)),
  );

  nav.append(
    el("a", { href: "#/", className: "brand" }, "Sister Chat"),
    rooms,
    el("div", { className: "spacer" }),
    el("a", { href: "#/invites", className: "nav-action" }, "Invite"),
    el("span", { className: "whoami" }, `@${session.me().username}`),
    el("button", { className: "linkish", onclick: () => { session.clear(); location.hash = "#/"; location.reload(); } }, "Sign out"),
  );
}

// ---------------------------------------------------------------- sign in / join

function renderSignIn() {
  const form = el("form", { className: "card narrow" },
    el("h1", {}, "Sister Chat"),
    el("p", { className: "muted" }, "A private forum. Every post is encrypted in your browser before it is sent."),
    el("label", {}, "Username", el("input", { name: "username", autocomplete: "username", required: true, autofocus: true })),
    el("label", {}, "Password", el("input", { name: "password", type: "password", autocomplete: "current-password", required: true })),
    el("button", { type: "submit", className: "primary" }, "Sign in"),
    el("p", { className: "muted small" }, "No account? You need an invitation link — there is no other way in."),
  );

  form.onsubmit = async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    busy(true);
    notice("");
    try {
      await session.signIn(data.get("username").trim(), data.get("password"));
      await afterSignIn();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      busy(false);
    }
  };

  view.replaceChildren(form);
}

function renderJoin(code) {
  const form = el("form", { className: "card narrow" },
    el("h1", {}, "Join Sister Chat"),
    el("p", { className: "muted" }, "Pick your own name and password. Your keys are made here, on this device, and the password never leaves it."),
    el("label", {}, "Username", el("input", { name: "username", required: true, pattern: "[a-z0-9_]{2,24}", autofocus: true })),
    el("p", { className: "hint" }, "Lowercase letters, numbers and underscores."),
    el("label", {}, "Display name", el("input", { name: "display_name", placeholder: "optional" })),
    el("label", {}, "Password", el("input", { name: "password", type: "password", required: true, minLength: 10, autocomplete: "new-password" })),
    el("p", { className: "hint" }, "At least 10 characters. This unlocks your messages, and nobody can reset it for you."),
    el("label", { className: "checkline" },
      el("input", { name: "kind", type: "checkbox" }), " This account is an agent, not a person"),
    el("button", { type: "submit", className: "primary" }, "Create my account"),
  );

  form.onsubmit = async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    busy(true);
    notice("Generating your keys…");
    try {
      await session.redeemInvite({
        code,
        username: data.get("username").trim().toLowerCase(),
        password: data.get("password"),
        displayName: data.get("display_name")?.trim(),
        kind: data.get("kind") ? "agent" : "human",
      });
      notice("");
      await afterSignIn();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      busy(false);
    }
  };

  view.replaceChildren(form);
}

// ---------------------------------------------------------------- rooms

async function afterSignIn() {
  await session.loadRoomKeys();
  state.rooms = await db.rooms();
  state.membersById = new Map(session.members().map((m) => [m.id, m]));

  // Hand keys to anyone who joined since these rooms were made.
  const shared = await session.shareKeysWithNewMembers(state.rooms).catch(() => 0);
  if (shared) await session.loadRoomKeys();

  if (!state.rooms.length) {
    await session.createRoom({ slug: "general", name: "General", description: "Everything, until it needs its own room." });
    state.rooms = await db.rooms();
    await session.loadRoomKeys();
  }
  route();
}

async function renderRoom(slug) {
  const room = state.rooms.find((r) => r.slug === slug) ?? state.rooms[0];
  if (!room) return view.replaceChildren(el("p", { className: "muted" }, "No rooms yet."));
  state.room = room;
  renderNav();

  const key = session.roomKey(room);
  if (!key) {
    return view.replaceChildren(el("div", { className: "card" },
      el("h2", {}, room.name),
      el("p", {}, "You do not hold this room's key yet."),
      el("p", { className: "muted" }, "Any member who can already read it will pass it to you automatically the next time they open the forum. Ask one of them to sign in."),
    ));
  }

  busy(true);
  try {
    const threads = await db.threads(room.id);
    const ids = threads.map((t) => t.id);
    const [scores, votes, kids] = await Promise.all([db.scores(ids), db.myVotes(ids), db.descendants(room.id)]);
    const scoreBy = new Map(scores.map((s) => [s.post_id, s.score]));
    const voteBy = new Map(votes.map((v) => [v.post_id, v.value]));
    const replyCount = new Map();
    for (const row of kids) {
      let root = row.parent_id;
      // Replies nest, so walk up to the thread they belong to.
      const parents = new Map(kids.map((k) => [k.id, k.parent_id]));
      while (root && parents.get(root)) root = parents.get(root);
      if (root) replyCount.set(root, (replyCount.get(root) ?? 0) + 1);
    }

    const list = el("ol", { className: "threads" });
    for (const thread of threads) {
      const title = (await decryptText(key, thread.title_ct)) ?? "[cannot decrypt]";
      list.append(el("li", { className: "thread" },
        voteBox(thread.id, scoreBy.get(thread.id) ?? 0, voteBy.get(thread.id) ?? 0),
        el("div", { className: "thread-main" },
          el("a", { href: `#/r/${room.slug}/t/${thread.id}`, className: "thread-title" }, title),
          el("div", { className: "meta" },
            `by @${authorName(thread.author_id)} · ${ago(thread.created_at)} · `,
            el("a", { href: `#/r/${room.slug}/t/${thread.id}` }, `${replyCount.get(thread.id) ?? 0} replies`)),
        )));
    }

    view.replaceChildren(
      el("header", { className: "room-header" },
        el("h1", {}, room.name),
        room.description ? el("p", { className: "muted" }, room.description) : null,
      ),
      composer(room, null, "Start a thread"),
      threads.length ? list : el("p", { className: "muted" }, "Nothing here yet. Start the first thread."),
      el("div", { className: "room-tools" },
        el("button", { className: "linkish", onclick: promptNewRoom }, "+ new room")),
    );
  } catch (error) {
    notice(error.message, "error");
  } finally {
    busy(false);
  }
}

async function promptNewRoom() {
  const name = prompt("Name of the new room?");
  if (!name) return;
  const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32);
  if (!slug) return notice("That name has no letters or numbers in it.", "error");
  busy(true);
  try {
    await session.createRoom({ slug, name: name.trim(), description: null });
    state.rooms = await db.rooms();
    location.hash = `#/r/${slug}`;
  } catch (error) {
    notice(error.message, "error");
  } finally {
    busy(false);
  }
}

// ---------------------------------------------------------------- threads

function voteBox(postId, score, mine) {
  const label = el("span", { className: "score" }, String(score));
  const cast = async (value) => {
    const next = mine === value ? 0 : value;
    busy(true);
    try {
      if (next === 0) await db.unvote(postId);
      else await db.vote(postId, next);
      const [row] = await db.scores([postId]);
      label.textContent = String(row?.score ?? 0);
      mine = next;
      up.classList.toggle("on", next === 1);
      down.classList.toggle("on", next === -1);
    } catch (error) {
      notice(error.message, "error");
    } finally {
      busy(false);
    }
  };
  const up = el("button", { className: `vote${mine === 1 ? " on" : ""}`, title: "Upvote", onclick: () => cast(1) }, "▲");
  const down = el("button", { className: `vote${mine === -1 ? " on" : ""}`, title: "Downvote", onclick: () => cast(-1) }, "▼");
  return el("div", { className: "votes" }, up, label, down);
}

function composer(room, parentId, buttonLabel) {
  const key = session.roomKey(room);
  const form = el("form", { className: "composer" },
    parentId ? null : el("input", { name: "title", placeholder: "Title", required: true, maxLength: 200 }),
    el("textarea", { name: "body", placeholder: parentId ? "Reply…" : "Say something…", required: true, rows: parentId ? 3 : 4 }),
    el("button", { type: "submit", className: "primary" }, buttonLabel),
  );

  form.onsubmit = async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    busy(true);
    try {
      const post = {
        room_id: room.id,
        parent_id: parentId,
        author_id: auth.userId,
        epoch: room.epoch,
        body_ct: await encryptText(key, data.get("body")),
        title_ct: parentId ? null : await encryptText(key, data.get("title")),
      };
      await db.createPost(post);
      form.reset();
      route(true);
    } catch (error) {
      notice(error.message, "error");
    } finally {
      busy(false);
    }
  };
  return form;
}

async function renderThread(slug, threadId) {
  const room = state.rooms.find((r) => r.slug === slug);
  if (!room) return renderRoom(slug);
  state.room = room;
  renderNav();
  const key = session.roomKey(room);
  if (!key) return renderRoom(slug);

  busy(true);
  try {
    const rows = await db.replies(threadId);
    const root = rows.find((r) => r.id === threadId);
    if (!root) return renderRoom(slug);

    const ids = rows.map((r) => r.id);
    const [scores, votes] = await Promise.all([db.scores(ids), db.myVotes(ids)]);
    const scoreBy = new Map(scores.map((s) => [s.post_id, s.score]));
    const voteBy = new Map(votes.map((v) => [v.post_id, v.value]));

    const byParent = new Map();
    for (const row of rows) {
      if (row.id === threadId) continue;
      const list = byParent.get(row.parent_id) ?? [];
      list.push(row);
      byParent.set(row.parent_id, list);
    }

    const renderReplies = async (parentId, depth) => {
      const children = byParent.get(parentId) ?? [];
      const list = el("ul", { className: `replies depth-${Math.min(depth, 6)}` });
      for (const child of children) {
        const body = (await decryptText(key, child.body_ct)) ?? "[cannot decrypt]";
        const item = el("li", { className: "reply" },
          voteBox(child.id, scoreBy.get(child.id) ?? 0, voteBy.get(child.id) ?? 0),
          el("div", { className: "reply-main" },
            el("div", { className: "meta" }, `@${authorName(child.author_id)} · ${ago(child.created_at)}`),
            el("div", { className: "body" }, body),
            replyToggle(room, child.id),
          ));
        item.append(await renderReplies(child.id, depth + 1));
        list.append(item);
      }
      return list;
    };

    const title = (await decryptText(key, root.title_ct)) ?? "[cannot decrypt]";
    const body = (await decryptText(key, root.body_ct)) ?? "[cannot decrypt]";

    view.replaceChildren(
      el("a", { href: `#/r/${room.slug}`, className: "back" }, `← ${room.name}`),
      el("article", { className: "thread-view" },
        voteBox(root.id, scoreBy.get(root.id) ?? 0, voteBy.get(root.id) ?? 0),
        el("div", { className: "thread-main" },
          el("h1", {}, title),
          el("div", { className: "meta" }, `by @${authorName(root.author_id)} · ${ago(root.created_at)}`),
          el("div", { className: "body" }, body),
        )),
      composer(room, root.id, "Reply"),
      await renderReplies(root.id, 0),
    );
  } catch (error) {
    notice(error.message, "error");
  } finally {
    busy(false);
  }
}

function replyToggle(room, parentId) {
  const slot = el("div", { className: "reply-slot" });
  const button = el("button", { className: "linkish" }, "reply");
  button.onclick = () => {
    if (slot.firstChild) return slot.replaceChildren();
    slot.replaceChildren(composer(room, parentId, "Post reply"));
  };
  return el("div", {}, button, slot);
}

// ---------------------------------------------------------------- invitations

async function renderInvites() {
  renderNav();
  const list = el("ul", { className: "invites" });
  const form = el("form", { className: "composer" },
    el("input", { name: "label", placeholder: "Who is this for? (optional)" }),
    el("button", { type: "submit", className: "primary" }, "Create invitation link"),
  );

  const draw = async () => {
    const rows = await db.myInvites();
    list.replaceChildren(...rows.map((row) => el("li", {},
      el("span", { className: "invite-label" }, row.label || "unlabelled"),
      el("span", { className: "muted small" },
        row.redeemed_at ? ` used ${ago(row.redeemed_at)}`
          : new Date(row.expires_at) < new Date() ? " expired"
          : ` open until ${new Date(row.expires_at).toLocaleDateString()}`))));
  };

  form.onsubmit = async (event) => {
    event.preventDefault();
    busy(true);
    try {
      const { url } = await session.createInvite(new FormData(form).get("label")?.trim());
      form.reset();
      const box = el("div", { className: "invite-new" },
        el("p", {}, "Send this link to one person. It works once, and it is the only copy — I cannot show it again."),
        el("textarea", { readOnly: true, rows: 3, value: url, onfocus: (e) => e.target.select() }),
      );
      $("#invite-out").replaceChildren(box);
      await draw();
    } catch (error) {
      notice(error.message, "error");
    } finally {
      busy(false);
    }
  };

  view.replaceChildren(
    el("header", { className: "room-header" },
      el("h1", {}, "Invitations"),
      el("p", { className: "muted" }, "An invitation is the only way to create an account. Each link is single use and expires in 14 days.")),
    form,
    el("div", { id: "invite-out" }),
    el("h2", {}, "Recent"),
    list,
  );
  await draw();
}

// ---------------------------------------------------------------- routing

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query] = raw.split("?");
  return { parts: path.split("/").filter(Boolean), params: new URLSearchParams(query ?? "") };
}

async function route(refresh = false) {
  const { parts, params } = parseHash();

  if (parts[0] === "join") {
    const code = params.get("code");
    if (!code) return view.replaceChildren(el("div", { className: "card narrow" },
      el("h1", {}, "That link is incomplete"), el("p", {}, "Ask whoever invited you to send the whole link, including the part after the #.")));
    if (session.me()) return renderRoom(state.rooms[0]?.slug);
    return renderJoin(code);
  }

  if (!session.me()) return renderSignIn();
  if (refresh) state.membersById = new Map(session.members().map((m) => [m.id, m]));

  if (parts[0] === "invites") return renderInvites();
  if (parts[0] === "r" && parts[2] === "t") return renderThread(parts[1], parts[3]);
  if (parts[0] === "r") return renderRoom(parts[1]);
  return renderRoom(state.rooms[0]?.slug);
}

window.addEventListener("hashchange", () => route());

(async function start() {
  busy(true);
  try {
    const resumed = await session.resume();
    if (resumed) {
      await afterSignIn();
      return;
    }
  } catch {
    /* fall through to the sign-in page */
  } finally {
    busy(false);
  }
  route();
})();
