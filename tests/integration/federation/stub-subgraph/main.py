"""Stand-in second subgraph used by the integration scenarios.

This is *not* a Tyk binary — it's a tiny aiohttp server that pretends to
be a Posts subgraph in a federation v2 supergraph. It owns
``type Post @key(fields: "id")`` with ``author: User! @external``, so when
Apollo Router resolves ``posts { author { username } }`` it has to fan out
to Tyk for the User entity. That fan-out is what we're trying to exercise.

Run it from this directory::

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python3 main.py --port 8001

The scenario scripts in ``../scenarios`` start it for you and pass
``--port`` on the command line. Stdout prints ``READY`` once the listener
is up so the scripts can wait for it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from aiohttp import web

# Federation v2.5 SDL for this subgraph. Note ``author`` is ``@external``:
# this subgraph holds the ``Post`` entity but does NOT own ``User``. That
# forces the router to compose with Tyk (which owns ``User``).
POSTS_SDL = """
extend schema
  @link(url: "https://specs.apollo.dev/federation/v2.5", import: ["@key", "@external"])

type Post @key(fields: "id") {
  id: ID!
  title: String!
  author: User! @external
}

type User @key(fields: "id") {
  id: ID! @external
}

type Query {
  posts: [Post!]!
  postById(id: ID!): Post
}
""".strip()

POSTS = [
    {"__typename": "Post", "id": "p1", "title": "First post",  "author": {"__typename": "User", "id": "1"}},
    {"__typename": "Post", "id": "p2", "title": "Second post", "author": {"__typename": "User", "id": "2"}},
]


async def health(_request: web.Request) -> web.Response:
    return web.Response(text="ok")


async def graphql(request: web.Request) -> web.Response:
    body = await request.json()
    query = body.get("query") or ""
    variables = body.get("variables") or {}

    # _service { sdl } - federation discovery
    if "_service" in query:
        return web.json_response({"data": {"_service": {"sdl": POSTS_SDL}}})

    # _entities resolver: rehydrate Post by id, return null otherwise.
    if "_entities" in query:
        reps = variables.get("representations") or []
        entities = []
        for rep in reps:
            if not isinstance(rep, dict):
                entities.append(None)
                continue
            if rep.get("__typename") != "Post":
                entities.append(None)
                continue
            match = next((p for p in POSTS if p["id"] == rep.get("id")), None)
            entities.append(match)
        return web.json_response({"data": {"_entities": entities}})

    # Plain queries.
    if "posts" in query and "postById" not in query:
        return web.json_response({"data": {"posts": POSTS}})

    if "postById" in query:
        target = variables.get("id") or ""
        match = next((p for p in POSTS if p["id"] == target), None)
        return web.json_response({"data": {"postById": match}})

    return web.json_response(
        {"errors": [{"message": f"Unsupported query: {query[:80]}"}]},
        status=400,
    )


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/", graphql)
    return app


async def serve(host: str, port: int) -> None:
    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    # Tell the scenario script the listener is up so it can move on.
    print(f"STUB_URL=http://{host}:{port}", flush=True)
    print("READY", flush=True)

    # Block forever; scenario scripts SIGTERM us.
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()

    try:
        asyncio.run(serve(args.host, args.port))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
