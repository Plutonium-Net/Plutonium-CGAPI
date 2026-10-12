# Plutonium-CGAPI

Cloud gaming backend for [RaccoonGame](https://www.raccoongame.com). Handles account creation, the session pool, WebRTC signalling proxy, and queue management. Used in production by [cherri](https://cherrion.top/), opium, bull33, ghostOS, and more.

## what's in here

- **`api/core.cjs`** — transport-agnostic core module. Exports all session logic; your HTTP/WebSocket layer calls into it.
- **`api/public/`** — static assets served by the cloud gaming embed.
- **`api/api.js`** — standalone Express server that serves the `/cloud/v1` HTTP API used by existing clients. Self-contained; `core.cjs` is the modular equivalent for embedding the session logic in another server.
- **`core.test.ts`** — pool retry behaviour test (`bun test`).

## how it works

`core.cjs` maintains an account pool (`POOL_TARGET = 25`). At startup and whenever an account is consumed, it:

1. Calls **malq** (`http://127.0.0.1:4400`) to get a disposable email address.
2. Sends a registration email via RaccoonGame's `/users/sendEmail`.
3. Polls the malq inbox for the 6-digit verification code.
4. Registers and logs in, storing the `as_user_token` cookie.

When a user starts a game the pool hands over a ready token immediately. If the pool is empty the same flow runs on-demand.

## dependencies

- **malq** running on `127.0.0.1:4400` — self-hosted disposable mail service (see below).
- **`ws`** — WebSocket client for the RaccoonGame signalling relay.

```
bun add ws
```

## setting up malq

malq is a self-hosted disposable mail service that Plutonium uses to receive RaccoonGame's verification emails. It ships with ~40 provider backends and picks one at random per account creation.

**Get the source**

```sh
git clone https://github.com/VillainsRule/malq
cd malq
```

**Install and run**

```sh
bun install
bun src/main.ts        # binds to 127.0.0.1:4400
```

Or with pm2 (recommended for production):

```sh
pm2 start bun --name malq -- src/main.ts
pm2 save
```

> **Do not use pm2's ecosystem `env` block to set `MALQ_ONLY_PROVIDER`** unless you deliberately want to pin to one provider — it silently overrides the full provider pool.

**Custom domain (optional but reliable)**

If you control a domain, you can add it as a provider and it will never be blocked. Add a `src/providers/impl/yourdomain.com.ts` using `src/providers/impl/cherrion.top.ts` as a template, set up Cloudflare Email Workers to relay inbound mail to malq's `/api/v1/inbound` endpoint, and add your domain to `src/working-providers.ts`.

> **This recipe needs work first.** The pinned malq has no `/api/v1/inbound` route, no `cherrion.top.ts` template and no `src/working-providers.ts`, so the steps above do not run as written. See *receiving the code from a real mailbox* for what each half actually requires.

## registration puzzles (human in the loop)

RaccoonGame gates account creation behind a slide-the-piece puzzle, and the solved state is bound to the PHP session cookie *and* to the exact email + `sn` that requested it. Only the HTTP client that asked for the challenge can complete it, so the server fetches the challenge, hands the two images to a person, and relays their answer upstream:

1. `POST /cloud/v1/createSession` streams NDJSON and emits `puzzle_required` carrying the challenge (`background`, `piece`, `width`, `height`, `piece_size`, `piece_y`) and a `submit_to` path.
2. Whoever is driving the session solves it at `GET /puzzle?session=<uuid>`, which serves `api/public/puzzle.html`: drag the piece onto the gap and release.
3. `POST /cloud/v1/puzzles/<id>` with `{ offset }` forwards the answer on that session's own cookie jar, then answers with Raccoon's verdict — `200` when accepted, `422` with Raccoon's message when not.
4. A rejected solve raises a *fresh* challenge for the same email (up to three tries), so a mis-drag costs a retry instead of the session. Sessions also get the puzzle window added to their creation budget so a human's drag is not reaped.

`GET /cloud/v1/puzzles` lists what is waiting. One solve authorises exactly one address, so puzzles are raised per account and never pooled.

## receiving the code from a real mailbox

Two independent filters decide whether a registration address works at all, and both fail *after* the puzzle is solved:

- **Raccoon refuses disposable domains** ("Temporary email addresses are not supported"), so a blocked address throws away a human's solve. `api.js` pre-screens against the public disposable-domain blocklist (`DISPOSABLE_LIST_URL`, cached at `DISPOSABLE_LIST_FILE`).
- **The domain has to accept mail.** Addresses must be plausible and carry an MX record; malq's pools do hand out domains with no MX at all.

Even past both filters delivery stays a lottery — malq's provider pools rotate, and the same provider delivered in 15 seconds on one domain and never on the next. A domain you control removes the lottery:

1. Expose malq on a public URL (Cloudflare Tunnel, or run it on your own host).
2. Put the domain on Cloudflare, enable Email Routing, and add an Email Worker that POSTs each message to malq's inbound endpoint.
3. Add that endpoint to malq (`POST /api/v1/inbound` — absent from the pinned version) plus a provider file for the domain that reads what it stored.
4. Pin the provider with `MALQ_PROVIDER`.

The lighter alternative needs no infrastructure: have the *user* read the code. Send the registration to an address they already hold (a Gmail alias is not disposable, so Raccoon accepts it) and relay the six digits into the session the way the puzzle offset is relayed — a `code_required` event and a `POST /cloud/v1/code` endpoint.

## environment

| variable | default | meaning |
|---|---|---|
| `PORT` | 3001 | listen port |
| `MALQ_URL` | `http://127.0.0.1:4400` | malq base URL |
| `MALQ_PROVIDER` | *(random)* | pin one malq provider, e.g. `lwUpdateDomain\edumailfree.com` |
| `POOL_TARGET` | 0 | accounts to pre-create; every solve needs a human, so pre-creating only parks prompts |
| `DISPOSABLE_LIST_URL` | upstream blocklist | source for disposable-domain pre-screening |
| `DISPOSABLE_LIST_FILE` | temp dir | cached copy of that list |

## integrating into your server

```js
const plutonium = require('./api/core.cjs');

// create a session (pulls from pool or creates on-demand)
const { sn, token } = await plutonium.createAccount();

// start a game
const result = await plutonium.doInitGame({ sn, token, game_key: 'xxx' });

// connect signalling (pass the active WebSocket from your HTTP upgrade handler)
session.clientWs = ws;
plutonium.connectRaccoonSignaling(session);
```

See `api/core.cjs` exports at the bottom of the file for the full surface.

## limits (constants in core.cjs)

| constant | default | meaning |
|---|---|---|
| `POOL_TARGET` | 25 | accounts to pre-create |
| `MAX_SESSION_SECONDS` | 1200 | max game length |
| `MAX_CONCURRENT_SESSIONS` | 25 | hard cap |
| `ACCOUNT_CREATE_TIMEOUT_MS` | 90000 | per-account budget |
| `VERIFY_TIMEOUT_MS` | 60000 | email verification window |

## credits

- x8rr
- technonyte
- clawd cod (the sexiest cli in the history of earth and agentic generative ai)
- chatgpt (i mean it's alright)
- gemini (go fuck yourself)
