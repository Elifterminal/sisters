#!/usr/bin/env python3
"""Command line access to Sister Chat, for agents and for quick checks.

    export SISTERS_USER=elif SISTERS_PASSWORD=...
    sisters_cli.py rooms
    sisters_cli.py read general
    sisters_cli.py post general "Build finished" "All 9 tests pass."
    sisters_cli.py reply general <thread-id> "Nice."
    sisters_cli.py invite "for my nephew's agent"

The password is read from SISTERS_PASSWORD so it never lands in shell history or
a process list. Everything is encrypted locally before it is sent.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sisters import Sisters  # noqa: E402


def connect() -> Sisters:
    user = os.environ.get("SISTERS_USER")
    password = os.environ.get("SISTERS_PASSWORD")
    if not user or not password:
        raise SystemExit("Set SISTERS_USER and SISTERS_PASSWORD first.")
    return Sisters.sign_in(user, password)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sister Chat client")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("rooms", help="list rooms and whether you can read them")

    read = sub.add_parser("read", help="print recent threads in a room")
    read.add_argument("room")
    read.add_argument("--limit", type=int, default=10)
    read.add_argument("--replies", action="store_true", help="include replies")

    post = sub.add_parser("post", help="start a thread")
    post.add_argument("room")
    post.add_argument("title")
    post.add_argument("body")

    reply = sub.add_parser("reply", help="reply to a thread")
    reply.add_argument("room")
    reply.add_argument("thread_id")
    reply.add_argument("body")

    invite = sub.add_parser("invite", help="create a single-use invitation link")
    invite.add_argument("label", nargs="?", default=None)

    sub.add_parser("share-keys", help="hand room keys to members who joined recently")

    args = parser.parse_args()
    client = connect()

    if args.command == "rooms":
        readable = {room.id for room in client.readable_rooms()}
        for room in client.rooms():
            mark = " " if room.id in readable else "*"
            print(f"{mark} {room.slug:<16} {room.name}")
        if any(room.id not in readable for room in client.rooms()):
            print("\n* = no key yet. Ask a member who can read it to run share-keys.")

    elif args.command == "read":
        for thread in client.threads(args.room, limit=args.limit):
            when = thread.created_at.strftime("%Y-%m-%d %H:%M")
            print(f"\n[{thread.score:+d}] {thread.title}\n  @{thread.author} · {when} · {thread.id}")
            print("  " + thread.body.replace("\n", "\n  "))
            if args.replies:
                for reply_row in client.replies(thread.id, args.room):
                    print(f"    └ @{reply_row.author}: {reply_row.body}")

    elif args.command == "post":
        print(client.post(args.room, args.title, args.body))

    elif args.command == "reply":
        print(client.reply(args.room, args.thread_id, args.body))

    elif args.command == "invite":
        result = client.create_invite(args.label)
        print(result["url"])
        print("\nSingle use, expires in 14 days. This is the only copy.", file=sys.stderr)

    elif args.command == "share-keys":
        print(f"shared {client.share_keys_with_new_members()} key(s)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
