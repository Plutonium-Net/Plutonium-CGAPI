const express = require("express");
const { randomUUID, createDecipheriv } = require("crypto");
const { readFileSync } = require("fs");
const os = require("os");
const { WebSocketServer, WebSocket } = require("ws");
const { createServer } = require("http");
const dns = require("dns");
const path = require("path");
const chalk = require("chalk");

if (!globalThis.crypto) globalThis.crypto = require("crypto").webcrypto;

const PORT = process.env.PORT || 3001;

// sites.json is looked up in the working directory first (so an operator can
// keep a per-deployment config outside the source tree), then next to this
// file — otherwise the server only starts when launched from its own folder.
function loadSites() {
  const candidates = [
    path.resolve("sites.json"),
    path.join(__dirname, "sites.json"),
  ];
  for (const candidate of candidates) {
    try {
      return JSON.parse(readFileSync(candidate, "utf-8"));
    } catch (err) {
      // A config that exists but is malformed must still fail loudly.
      if (err?.code !== "ENOENT") throw err;
    }
  }
  throw new Error(`no sites.json found (looked in ${candidates.join(", ")})`);
}

let sites;
try {
  sites = loadSites();
} catch (e) {
  console.error("Failed to load sites.json:", e);
  process.exit(1);
}

const RACCOON_HOST = "www.raccoongame.com";
const RACCOON_TIMEOUT_MS = 20_000;
let raccoonIpCache = null;

async function resolveRaccoonIp() {
  if (raccoonIpCache && raccoonIpCache.expiresAt > Date.now())
    return raccoonIpCache;
  for (const family of [4, 6]) {
    try {
      const addrs =
        family === 4
          ? await dns.promises.resolve4(RACCOON_HOST)
          : await dns.promises.resolve6(RACCOON_HOST);
      if (addrs?.length) {
        const ip = addrs[Math.floor(Math.random() * addrs.length)];
        raccoonIpCache = { ip, family, expiresAt: Date.now() + 5 * 60_000 };
        return raccoonIpCache;
      }
    } catch {}
  }
  return null;
}

async function fetchWithTimeout(url, opts = {}, ms = RACCOON_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Raccoon's registration puzzle is bound to the PHP session that requested it,
// so an account being created has to carry that session's cookies between
// calls. fetch keeps no cookie state, so the caller passes a jar explicitly.
function newRaccoonJar() {
  return { cookies: new Map() };
}

function jarCookieHeader(jar) {
  if (!jar || jar.cookies.size === 0) return undefined;
  return [...jar.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
}

function absorbCookies(jar, res) {
  if (!jar || typeof res.headers.getSetCookie !== "function") return;
  for (const raw of res.headers.getSetCookie()) {
    const pair = raw.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq > 0) jar.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}

async function raccoonFetch(pathAndQuery, opts = {}) {
  const { jar, ...init } = opts;
  const cookie = jarCookieHeader(jar);
  const headers = cookie
    ? { ...init.headers, Cookie: cookie }
    : { ...init.headers };
  const entry = await resolveRaccoonIp();
  let res;
  if (!entry) {
    res = await fetchWithTimeout(`https://${RACCOON_HOST}${pathAndQuery}`, {
      ...init,
      headers,
    });
  } else {
    const authority = entry.family === 6 ? `[${entry.ip}]` : entry.ip;
    try {
      res = await fetchWithTimeout(`https://${authority}${pathAndQuery}`, {
        ...init,
        headers: { ...headers, Host: RACCOON_HOST },
      });
    } catch {
      raccoonIpCache = null;
      res = await fetchWithTimeout(`https://${RACCOON_HOST}${pathAndQuery}`, {
        ...init,
        headers,
      });
    }
  }
  absorbCookies(jar, res);
  return res;
}

const sessions = new Map();
const siteUsage = new Map();
const ipLimits = new Map();
const embedIpLimits = new Map();
const accountCreating = new Map();

const MAX_SESSION_SECONDS = 19 * 60;

function decryptPayload(result) {
  const key = Buffer.from("fd39e724f7c1e4b3d34bc7c72b5349c3", "utf8");
  const iv = Buffer.from("dd39e4a3337fe25a", "utf8");
  const d = createDecipheriv("aes-256-cbc", key, iv);
  const raw = d.update(result, "base64", "utf8") + d.final("utf8");
  const parsed = JSON.parse(raw);
  if (parsed === null || typeof parsed !== "object")
    throw new Error("decryptPayload: unexpected shape");
  return parsed;
}

function generateSN() {
  return randomUUID().replace(/-/g, "").toLowerCase();
}

function generatePassword() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$";
  let p = "";
  for (let i = 0; i < 12; i++)
    p += chars[Math.floor(Math.random() * chars.length)];
  return p;
}

// malq is Plutonium's self-hosted disposable mail service (see README). It
// hands out an inbox on demand and needs no credentials. mail.tm is no longer
// usable for registrations: Raccoon refuses its single domain as a temporary
// address, while malq's provider domains are accepted.
const MAIL_HOST = process.env.MALQ_URL || "http://127.0.0.1:4400";
const MAIL_TIMEOUT_MS = 10_000;

async function mailFetch(pathAndQuery, opts = {}, ms = MAIL_TIMEOUT_MS) {
  let res;
  try {
    res = await fetchWithTimeout(`${MAIL_HOST}${pathAndQuery}`, opts, ms);
  } catch (cause) {
    const err = new Error(
      `malq unavailable at ${MAIL_HOST}: ${cause?.message || cause}`,
    );
    err.service = "malq";
    throw err;
  }
  const body = await res.text();
  if (!res.ok) {
    let detail = body.slice(0, 160);
    try {
      const parsed = JSON.parse(body);
      if (parsed?.error) detail = parsed.error;
    } catch {}
    throw new Error(
      `malq ${pathAndQuery.split("?")[0]} → HTTP ${res.status} ${detail}`,
    );
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new Error(`malq ${pathAndQuery.split("?")[0]} returned non-JSON`);
  }
}

// Raccoon's mail puts the code next to the word "code"; a mail that only carries
// a bare number is matched as a standalone token, so unrelated six-digit values
// embedded in markup are not mistaken for the code.
function extractVerificationCode(text) {
  const labelled = text.match(
    /(?:verification\s*code|验证码|verification|code)\D{0,24}?(\d{6})\b/i,
  );
  if (labelled) return labelled[1];
  const bare = text.match(/(?:^|[\s>])(\d{6})(?:\s|$)/);
  return bare ? bare[1] : null;
}

// Polls the malq inbox for Raccoon's 6-digit code. A provider that fails on
// every poll would otherwise burn the whole window silently, so the last error
// is carried into the timeout message.
async function getVerificationCode(mailToken, maxAttempts = 40) {
  let lastError = null;
  let announced = false;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 3000));
    try {
      const { mail } = await mailFetch(
        `/api/v1/inbox/${encodeURIComponent(mailToken)}`,
      );
      const messages = Array.isArray(mail) ? mail : [];
      if (messages.length && !announced) {
        // Worth knowing separately from the code: mail arriving but the code
        // not parsing is a very different bug from mail never arriving.
        announced = true;
        logSys(chalk.gray(`mail: ${messages.length} message(s) arrived`));
      }
      for (const msg of messages.slice(0, 10)) {
        const subject = String(msg?.subject ?? "");
        const text = [subject, String(msg?.body ?? "")]
          .join(" ")
          .replace(/<[^>]*>/g, " ")
          .replace(/&nbsp;/g, " ");
        const code = extractVerificationCode(text);
        if (code) {
          logSys(chalk.gray(`mail: code found in "${subject.slice(0, 48)}"`));
          return code;
        }
        // A message that arrives without a parseable code is a different bug
        // from one that never arrives, so show what it actually contained.
        logSys(
          chalk.yellow(
            `mail: no 6-digit code in "${subject.slice(0, 48)}" — ` +
              text.replace(/\s+/g, " ").trim().slice(0, 140),
          ),
        );
      }
    } catch (e) {
      lastError = e;
    }
  }
  throw new Error(
    "Timeout getting verification code" +
      (lastError ? ` (${lastError.message})` : ""),
  );
}

// Raccoon gates registration behind a slide-the-piece puzzle. The solved state
// is bound to the PHP session cookie *and* to the exact email+sn that requested
// the challenge, so only the same HTTP client can complete it — the server, not
// the end user's browser. So the server fetches the challenge, hands the two
// images to a human, and relays their answer back upstream. One solve
// authorises exactly one address, so puzzles are raised on demand.
const PUZZLE_TIMEOUT_MS = 10 * 60_000;
const pendingPuzzles = new Map(); // id -> { id, session, email, challenge, resolve }

function isPuzzleRefusal(text) {
  return /puzzle verification/i.test(text || "");
}

// Fetches a challenge on this jar's session and parks it for a human, invoking
// onPuzzle so whoever is streaming the session can render it. Resolves with the
// offset once the human's answer has been relayed upstream and accepted.
async function completePuzzle({
  jar,
  email,
  sn,
  headers,
  onPuzzle,
  sessionUuid,
}) {
  const qs = new URLSearchParams({
    email,
    type: "register",
    sn,
    t: String(Date.now()),
  });
  const cRes = await raccoonFetch(`/users/emailRegisterCaptcha?${qs}`, { jar });
  const cBody = await cRes.json().catch(() => null);
  const challenge = cBody?.data;
  if (!challenge?.challenge_id) {
    throw new Error(
      `puzzle challenge unavailable — HTTP ${cRes.status} ${cBody?.msg || ""}`.trim(),
    );
  }

  const id = randomUUID();
  // Whoever submitted the offset is told the *upstream* verdict, not just that
  // the answer was received — "puzzle does not match" is the whole point.
  let settleVerdict;
  const verdict = new Promise((resolve) => {
    settleVerdict = resolve;
  });
  const entry = {
    id,
    session: sessionUuid || null,
    email,
    challenge,
    created_at: Date.now(),
    verdict,
    settle: (v) => settleVerdict(v),
  };
  pendingPuzzles.set(id, entry);
  logSys(
    chalk.yellow(`puzzle required → ${chalk.white(id.slice(0, 8))} · ${email}`),
  );

  let offset;
  try {
    offset = await new Promise((resolve, reject) => {
      entry.resolve = resolve;
      entry.timer = setTimeout(() => {
        pendingPuzzles.delete(id);
        reject(new Error("puzzle solve timed out"));
      }, PUZZLE_TIMEOUT_MS);
      entry.timer.unref?.();
      onPuzzle?.(entry);
    });
  } catch (e) {
    entry.settle({ ok: false, message: e.message });
    throw e;
  } finally {
    clearTimeout(entry.timer);
    pendingPuzzles.delete(id);
  }

  try {
    const vRes = await raccoonFetch("/users/emailRegisterCaptchaVerify", {
      method: "POST",
      jar,
      headers,
      body: new URLSearchParams({
        email,
        type: "register",
        sn,
        challenge_id: challenge.challenge_id,
        offset: String(offset),
      }),
    });
    const vBody = await vRes.json().catch(() => null);
    if (vBody?.status !== 200) {
      const message = vBody?.msg || `HTTP ${vRes.status}`;
      entry.settle({ ok: false, message });
      throw new Error(`puzzle rejected — ${message}`);
    }
    entry.settle({ ok: true, message: "Raccoon accepted the offset." });
    logSys(chalk.green(`puzzle solved → ${chalk.white(id.slice(0, 8))}`));
    return offset;
  } catch (e) {
    entry.settle({ ok: false, message: e.message });
    throw e;
  }
}

// Sends the registration email, completing the puzzle gate once if Raccoon asks
// for it. Raccoon answers HTTP 200 even when it refuses, so the body's own
// `status` is the real outcome.
async function requestRegistrationEmail({
  jar,
  email,
  sn,
  base,
  headers,
  onPuzzle,
  sessionUuid,
}) {
  const attempt = async () => {
    const res = await raccoonFetch("/users/sendEmail", {
      method: "POST",
      jar,
      headers,
      body: new URLSearchParams({ email, type: "register", ...base }),
    });
    const raw = await res.text();
    let data = null;
    try {
      data = JSON.parse(raw);
    } catch {}
    return { res, raw, data };
  };

  let { res, raw, data } = await attempt();

  // A human's drag can land wrong, and Raccoon then refuses that challenge for
  // good — so raise a fresh one instead of losing the whole account flow.
  const MAX_PUZZLE_TRIES = 3;
  for (let tries = 0; tries < MAX_PUZZLE_TRIES; tries++) {
    if (!isPuzzleRefusal(data?.msg) && !isPuzzleRefusal(raw)) break;
    try {
      await completePuzzle({ jar, email, sn, headers, onPuzzle, sessionUuid });
    } catch (e) {
      logSys(chalk.red(`puzzle: attempt ${tries + 1} failed — ${e.message}`));
      if (tries === MAX_PUZZLE_TRIES - 1) throw e;
      continue; // the next pass fetches a fresh challenge
    }
    ({ res, raw, data } = await attempt());
  }

  if (
    !res.ok ||
    (data && typeof data.status === "number" && data.status !== 200)
  ) {
    throw new Error(
      `sendEmail rejected — HTTP ${res.status}` +
        (data?.msg ? ` · ${data.msg}` : ` · ${raw.slice(0, 160)}`),
    );
  }
  return data;
}

// Every account now needs a human to drag its registration puzzle, so a pool
// that nobody is watching only accumulates unsolvable prompts and holds account
// slots for them. Off by default; set POOL_TARGET to pre-create deliberately.
const POOL_TARGET = Math.max(0, Number(process.env.POOL_TARGET ?? 0) || 0);
const pool = [];
let poolFilling = false;

async function fillPool() {
  if (poolFilling) return;
  const needed = POOL_TARGET - pool.length;
  if (needed <= 0) return;
  poolFilling = true;
  try {
    for (let i = 0; i < needed; i++) {
      try {
        const acc = await createAccountRaw();
        pool.push(acc);
        logSys(chalk.gray(`pool: ready (${pool.length}/${POOL_TARGET})`));
      } catch (e) {
        logSys(chalk.red(`pool: fill error — ${e.message}`));
        break;
      }
    }
  } finally {
    poolFilling = false;
  }
}

async function createAccount(opts = {}) {
  if (pool.length > 0) {
    const acc = pool.shift();
    logSys(chalk.gray(`pool: served account (${pool.length} remaining)`));
    fillPool().catch(() => {});
    return acc;
  }
  logSys(chalk.gray("pool: miss — creating account on demand"));
  const acc = await createAccountRaw(opts);
  fillPool().catch(() => {});
  return acc;
}

// Raccoon refuses disposable domains outright — but only *after* the puzzle, so
// a blocked address throws away a human's solve. Pre-screen against the public
// disposable-domain blocklist; the list is optional, and if it cannot be read
// the check is skipped rather than blocking account creation.
const DISPOSABLE_LIST_URL =
  process.env.DISPOSABLE_LIST_URL ||
  "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf";
const DISPOSABLE_LIST_FILE =
  process.env.DISPOSABLE_LIST_FILE ||
  path.join(os.tmpdir(), "plutonium-disposable-domains.txt");
let disposableDomains = null;

async function getDisposableDomains() {
  if (disposableDomains) return disposableDomains;
  let text = null;
  try {
    text = readFileSync(DISPOSABLE_LIST_FILE, "utf-8");
  } catch {
    try {
      const res = await fetchWithTimeout(DISPOSABLE_LIST_URL, {}, 10_000);
      text = await res.text();
    } catch (e) {
      logSys(
        chalk.yellow(
          `mail: disposable-domain list unavailable (${e.message}) — skipping that check`,
        ),
      );
      disposableDomains = new Set();
      return disposableDomains;
    }
  }
  disposableDomains = new Set(
    text
      .split(/\s+/)
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean),
  );
  logSys(
    chalk.gray(`mail: disposable-domain list loaded (${disposableDomains.size})`),
  );
  return disposableDomains;
}

// malq's provider pools include domains with no MX record at all, and a mailbox
// on one of those can never receive Raccoon's code; others are on Raccoon's
// blocklist. Ask for an address that clears both before spending a solve on it.
async function mailSessionWithDeliverableDomain(providerQs, tries = 6) {
  let blockedButDeliverable = null;
  let last = null;
  let lastError = null;
  for (let i = 0; i < tries; i++) {
    let box;
    try {
      box = await mailFetch(`/api/v1/session${providerQs}`);
    } catch (e) {
      // Providers fail transiently (upstream 500s, provider-side WAF); that is
      // not a reason to abort a launch that has not started yet.
      lastError = e;
      logSys(chalk.yellow(`mail: ${e.message} — trying again`));
      continue;
    }
    if (!box?.address || !box?.token) throw new Error("malq returned no session");
    last = box;
    const domain = String(box.address).split("@")[1] || "";
    // Some provider pools are full of junk ("name@undefined", reverse-DNS arpa
    // names), so require something that is even a plausible mail domain before
    // spending a DNS lookup on it.
    const plausible =
      /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(
        domain,
      ) && !/\.arpa$/i.test(domain);
    if (!plausible) {
      logSys(chalk.yellow(`mail: malq offered ${box.address} — asking again`));
      continue;
    }
    try {
      const mx = await dns.promises.resolveMx(domain);
      if (!mx?.length) throw Object.assign(new Error("no MX"), { code: "ENOTFOUND" });
    } catch (e) {
      logSys(
        chalk.yellow(
          `mail: ${domain} cannot receive mail (${e.code || e.message}) — asking malq again`,
        ),
      );
      continue;
    }
    if ((await getDisposableDomains()).has(domain)) {
      logSys(
        chalk.yellow(
          `mail: ${domain} is on the disposable blocklist — asking malq again`,
        ),
      );
      blockedButDeliverable = blockedButDeliverable || box;
      continue;
    }
    return box;
  }
  if (blockedButDeliverable) {
    logSys(
      chalk.yellow(
        `mail: only blocklisted domains on offer; using ${blockedButDeliverable.address} anyway`,
      ),
    );
    return blockedButDeliverable;
  }
  if (!last) throw lastError || new Error("malq returned no inbox");
  logSys(
    chalk.yellow(
      `mail: no deliverable domain in ${tries} tries — using ${last.address}`,
    ),
  );
  return last;
}

async function createAccountRaw(opts = {}) {
  // The jar carries the Raccoon session across the mailbox, puzzle and register
  // calls; a puzzle solved here only counts for this jar and this email.
  const jar = opts.jar || newRaccoonJar();
  // malq picks the provider and creates the inbox itself, unlike mail.tm which
  // needed a domain lookup, an account and a token before mail could arrive.
  // malq has one provider per domain and Raccoon refuses some of those domains
  // outright, so pin the accepted one instead of gambling on a random pick.
  const providerQs = process.env.MALQ_PROVIDER
    ? `?provider=${encodeURIComponent(process.env.MALQ_PROVIDER)}`
    : "";
  const box = await mailSessionWithDeliverableDomain(providerQs);
  const email = box?.address;
  const mailToken = box?.token;
  if (!email || !mailToken) throw new Error("malq returned no session");
  logSys(chalk.gray(`mail: ${email} · ${box.provider || "unknown provider"}`));

  const raccoonPassword = generatePassword();
  const sn = generateSN();

  const h = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/147.0.0.0 Safari/537.36",
  };
  const base = {
    sn,
    model: "Chrome/147.0.0.0",
    version_code: "1",
    version_name: "1.0.0",
    device_name: "我的设备",
    os: "web",
  };

  await requestRegistrationEmail({
    jar,
    email,
    sn,
    base,
    headers: h,
    onPuzzle: opts.onPuzzle,
    sessionUuid: opts.sessionUuid,
  });

  const code = await getVerificationCode(mailToken);

  // The register reply is the only place a rejected code shows up; ignoring it
  // made every failure surface one step later as a bare "Login failed".
  const regRes = await raccoonFetch("/users/emailRegister", {
    method: "POST",
    jar,
    headers: h,
    body: new URLSearchParams({
      email,
      code,
      password: raccoonPassword,
      phone: "1",
      country: "Brazil",
      ...base,
    }),
  });
  const regBody = await regRes.json().catch(() => null);
  if (
    regRes.status !== 200 ||
    (regBody && typeof regBody.status === "number" && regBody.status !== 200)
  ) {
    throw new Error(
      `registration rejected — HTTP ${regRes.status}` +
        (regBody?.msg ? ` · ${regBody.msg}` : ` · code ${code}`),
    );
  }

  const loginRes = await raccoonFetch("/users/emailLogin", {
    method: "POST",
    jar,
    headers: h,
    body: new URLSearchParams({ email, password: raccoonPassword, ...base }),
  });
  const loginData = await loginRes.json();
  if (loginData.status !== 200) throw new Error("Login failed");

  let userToken = loginData.data?.user_token || "";
  const cookie = loginRes.headers.get("set-cookie");
  if (cookie) {
    const m = cookie.match(/as_user_token=([^;]+)/);
    if (m) userToken = m[1];
  }

  return { sn, token: userToken };
}

function gameHeaders(token) {
  return {
    accept: "*/*",
    "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
    cookie: `as_user_token=${token}`,
    origin: "https://www.raccoongame.com",
    referer: "https://www.raccoongame.com/?t=1720436119",
    "user-agent":
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/147.0.0.0 Safari/537.36",
    "x-requested-with": "XMLHttpRequest",
  };
}

async function doInitGame(session) {
  const { sn, token, game_key } = session;
  const h = gameHeaders(token);
  const common = {
    sn,
    model: "Chrome/147.0.0.0",
    version_code: "1",
    version_name: "1.0.0",
    device_name: "我的设备",
    os: "web",
    "manufacturer;": "",
    user_token: token,
  };

  await raccoonFetch("/userGame/checkCost", {
    method: "POST",
    headers: h,
    body: new URLSearchParams({ ...common, game_key }),
  });

  const playData = await (
    await raccoonFetch("/jyapi/playGame", {
      method: "POST",
      headers: h,
      body: new URLSearchParams({
        ...common,
        game_key,
        model_name: "Chrome/147.0.0.0",
      }),
    })
  ).json();

  if (
    playData.status === 201 ||
    (playData.status === 200 && playData.data?.play_queue_id)
  ) {
    const qid = playData.data?.play_queue_id;
    if (!qid) throw new Error("Missing queue ID");
    return {
      queued: true,
      queue_id: qid,
      initial_pos: playData.data?.queue_pos,
    };
  }
  if (playData.status === 200 && playData.data?.result) {
    const server_data = decryptPayload(playData.data.result);
    return { queued: false, server_data };
  }

  throw new Error(`Unexpected playGame response: ${JSON.stringify(playData)}`);
}

async function doPollQueue(session, queue_id) {
  const { sn, token } = session;
  const d = await (
    await raccoonFetch("/jyapi/playQueue", {
      method: "POST",
      headers: gameHeaders(token),
      body: new URLSearchParams({
        sn,
        model: "Chrome/147.0.0.0",
        version_code: "1",
        version_name: "1.0.0",
        device_name: "我的设备",
        os: "web",
        "manufacturer;": "",
        play_queue_id: queue_id,
        user_token: token,
      }),
    })
  ).json();
  if (d.status !== 200 && d.status !== 201)
    throw new Error(`Queue poll rejected: ${JSON.stringify(d)}`);
  return d.data?.queue_pos ?? 1;
}

async function doClaimGame(session, queue_id) {
  const { sn, token, game_key } = session;
  const d = await (
    await raccoonFetch("/jyapi/playGame", {
      method: "POST",
      headers: gameHeaders(token),
      body: new URLSearchParams({
        sn,
        model: "Chrome/147.0.0.0",
        version_code: "1",
        version_name: "1.0.0",
        device_name: "我的设备",
        os: "web",
        "manufacturer;": "",
        game_key,
        model_name: "Chrome/147.0.0.0",
        play_queue_id: queue_id,
        user_token: token,
      }),
    })
  ).json();
  if (d.status === 200 && d.data?.result) return decryptPayload(d.data.result);
  throw new Error(`Failed to claim game. API Status: ${d.status}`);
}

async function doStopGame(session) {
  clearInterval(session.raccoonPingInterval);
  session.raccoonWs?.close();
  if (!session.sc_id) return;
  try {
    await raccoonFetch("/jyapi/stopGame", {
      method: "POST",
      headers: gameHeaders(session.token),
      body: new URLSearchParams({
        sn: session.sn,
        model: "Chrome/147.0.0.0",
        version_code: "1",
        version_name: "1.0.0",
        device_name: "我的设备",
        os: "web",
        "manufacturer;": "",
        sc_id: String(session.sc_id),
        game_type: "1",
        user_token: session.token,
      }),
    });
  } catch {}
}

async function doCost(session) {
  if (!session.sc_id) return;
  try {
    const res = await raccoonFetch("/userGame/cost", {
      method: "POST",
      headers: gameHeaders(session.token),
      body: new URLSearchParams({
        sn: session.sn,
        model: "Chrome/147.0.0.0",
        version_code: "1",
        version_name: "1.0.0",
        device_name: "我的设备",
        os: "web",
        "manufacturer;": "",
        sc_id: String(session.sc_id),
        game_type: "1",
        user_token: session.token,
      }),
    });
    const body = await res.json().catch(() => null);
    logApi(
      session.api_key,
      chalk.gray(`doCost → ${res.status} ${JSON.stringify(body)}`),
    );
    if (body?.status === 3013) {
      killSession(session.uuid, "upstream_terminated");
    }
  } catch (e) {
    logApi(session.api_key, chalk.red(`doCost error: ${e.message}`));
  }
}

function timestamp() {
  const now = new Date();
  const time = now.toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  });
  const date = now.toLocaleDateString("en-US", {
    month: "numeric",
    day: "numeric",
    year: "2-digit",
  });
  return chalk.blackBright(`[${time} ${date}]`);
}

function logApi(apiKey, message) {
  const name = getSiteName(apiKey) || "unknown";
  console.log(`${timestamp()} ${chalk.cyan(name)} ${message}`);
}

function logSys(message) {
  console.log(`${timestamp()} ${chalk.magenta("plutonium")} ${message}`);
}

function getClientIp(req) {
  const caddy = req.headers["x-caddy-real-ip-is-here1357908642"];
  if (caddy) return caddy;
  return req.socket.remoteAddress || "unknown";
}

function checkIpLimit(store, ip, windowMs, max) {
  const now = Date.now();
  const hits = (store.get(ip) || []).filter((t) => t > now - windowMs);
  if (hits.length >= max) return false;
  hits.push(now);
  store.set(ip, hits);
  return true;
}

function getSiteName(apiKey) {
  return (
    Object.keys(sites.sites).find((k) => sites.sites[k].api_key === apiKey) ||
    null
  );
}

function getSite(apiKey) {
  const name = getSiteName(apiKey);
  return name ? { name, ...sites.sites[name] } : null;
}

function checkRateLimit(apiKey, site) {
  const now = Date.now();
  const calls = siteUsage.get(apiKey) || [];

  const perMin = calls.filter((t) => t > now - 60_000).length;
  const perHour = calls.filter((t) => t > now - 3_600_000).length;
  const perDay = calls.filter((t) => t > now - 86_400_000).length;
  const perMonth = calls.filter((t) => t > now - 30 * 86_400_000).length;

  if (perMin >= site.limits.per_minute)
    return {
      allowed: false,
      reason: `per-minute limit (${site.limits.per_minute}/min)`,
    };
  if (perHour >= site.limits.per_hour)
    return {
      allowed: false,
      reason: `per-hour limit (${site.limits.per_hour}/hr)`,
    };
  if (perDay >= site.limits.per_day)
    return {
      allowed: false,
      reason: `per-day limit (${site.limits.per_day}/day)`,
    };
  if (perMonth >= site.limits.per_month)
    return {
      allowed: false,
      reason: `per-month limit (${site.limits.per_month}/month)`,
    };

  return { allowed: true };
}

function recordUsage(apiKey) {
  const now = Date.now();
  const calls = (siteUsage.get(apiKey) || []).filter(
    (t) => t > now - 30 * 86_400_000,
  );
  calls.push(now);
  siteUsage.set(apiKey, calls);
}

function getUsageStats(apiKey) {
  const now = Date.now();
  const calls = siteUsage.get(apiKey) || [];
  return {
    perMin: calls.filter((t) => t > now - 60_000).length,
    perHour: calls.filter((t) => t > now - 3_600_000).length,
    perDay: calls.filter((t) => t > now - 86_400_000).length,
    perMonth: calls.filter((t) => t > now - 30 * 86_400_000).length,
  };
}

function countActiveSessions(apiKey) {
  return [...sessions.values()].filter((s) => s.api_key === apiKey).length;
}

function acquireAccountSlot(apiKey, site) {
  const cap = (site.max_concurrent_sessions ?? 5) * 2;
  const current = accountCreating.get(apiKey) ?? 0;
  if (current >= cap) return false;
  accountCreating.set(apiKey, current + 1);
  return true;
}

function releaseAccountSlot(apiKey) {
  const current = accountCreating.get(apiKey) ?? 1;
  const next = current - 1;
  if (next <= 0) accountCreating.delete(apiKey);
  else accountCreating.set(apiKey, next);
}

function applyServerData(session, sd) {
  session.sc_id = sd.sc_id || sd.play_id;
  session.bs_sc_id = sd.bs_sc_id || session.sc_id;
  session.bs_host = sd.bs_host;
  session.bs_token = sd.token;
  session.channel_id = sd.channel_id;
  session.gl_key = sd.gl_key;
  session.play_config = sd.play_config;
  session.turns = sd.turns || [];
  session.message_server = sd.message_server;
}

function killSession(uuid, reason = "unknown") {
  const session = sessions.get(uuid);
  if (!session) return;

  clearTimeout(session.startgame_timeout);
  clearTimeout(session.queue_abandon_timeout);
  clearTimeout(session.ping_timeout);
  clearTimeout(session.session_timeout);
  clearInterval(session.costInterval);

  try {
    session.clientWs?.close(1000, reason);
  } catch {}

  doStopGame(session).catch(() => {});
  sessions.delete(uuid);

  logApi(
    session.api_key,
    chalk.gray(`session ${chalk.white(uuid.slice(0, 8))} killed — ${reason}`),
  );
}

function resetPingTimeout(uuid) {
  const session = sessions.get(uuid);
  if (!session) return;
  clearTimeout(session.ping_timeout);
  session.ping_timeout = setTimeout(
    () => killSession(uuid, "ping_timeout"),
    30_000,
  );
}

const REAPER_DEADLINES = {
  creating: 5 * 60_000,
  finished_queue: 2 * 60_000,
};
const QUEUED_MAX_AGE = 30 * 60_000;
const QUEUED_POLL_STALE_AFTER = 90_000;

setInterval(() => {
  const now = Date.now();
  for (const [uuid, session] of sessions) {
    if (session.state === "queued") {
      const lastSeen = session.last_queue_poll_at ?? session.created_at;
      if (
        now - lastSeen > QUEUED_POLL_STALE_AFTER ||
        now - session.created_at > QUEUED_MAX_AGE
      ) {
        killSession(uuid, "reaper:queued_stale");
      }
      continue;
    }
    const deadline = REAPER_DEADLINES[session.state];
    if (deadline !== undefined) {
      // A human dragging this session's registration puzzle — and the mailbox
      // wait that follows — legitimately outlives ordinary account creation, so
      // a session that raised a puzzle gets the puzzle window on top.
      const budget = session.puzzle_raised_at
        ? deadline + PUZZLE_TIMEOUT_MS
        : deadline;
      if (now - session.created_at > budget) {
        killSession(uuid, `reaper:${session.state}_deadline`);
        continue;
      }
    }
    if (session.state === "active" && !session.session_timeout) {
      killSession(uuid, "reaper:active_no_timeout");
    }
  }
}, 2 * 60_000).unref?.();

function connectRaccoonSignaling(session) {
  const { sn, gl_key, play_config, uuid } = session;

  const raccoonWs = new WebSocket(session.message_server.url);
  session.raccoonWs = raccoonWs;

  const rSend = (p) => {
    if (raccoonWs.readyState === WebSocket.OPEN)
      raccoonWs.send(JSON.stringify(p));
  };
  const toClient = (data) => {
    const cws = session.clientWs;
    if (cws?.readyState === WebSocket.OPEN) cws.send(JSON.stringify(data));
  };

  raccoonWs.on("open", () => {
    rSend({
      id: "register",
      type: "webUA",
      uid: sn,
      token: decodeURIComponent(session.message_server.token),
    });
    session.raccoonPingInterval = setInterval(() => {
      rSend({
        id: "ping",
        uid: sn,
        type: "webUA",
        status: "gaming",
        sc_id: session.bs_sc_id,
      });
    }, 30_000);
  });

  raccoonWs.on("message", (raw) => {
    let data;
    try {
      data = JSON.parse(raw.toString());
    } catch {
      return;
    }

    switch (data.id) {
      case "register_ack":
        if (data.code === 200) {
          rSend({
            id: "start_game",
            from: sn,
            to: gl_key,
            game_args: "",
            gp_num: 0,
            play_config,
            simpleHandler: null,
            body: {
              force_soft_dec: 0,
              session_id: session.bs_sc_id,
              sn_user_id: sn,
              game_name: null,
              joystick_num: 2,
            },
          });
        }
        break;

      case "start_game":
        if (data.from === gl_key && data.body?.code === 200) {
          toClient({ type: "game_ready" });
        }
        break;

      case "rtc_sdp": {
        const b = data.body;
        if (!b) break;
        try {
          if (b.type === "answer") {
            toClient({ type: "rtc_answer", sdp: b });
          } else if (b.type === "candidate" && b.sdp) {
            toClient({ type: "rtc_candidate", candidate: b.sdp });
          }
        } catch {}
        break;
      }
    }
  });

  raccoonWs.on("close", () => clearInterval(session.raccoonPingInterval));
  raccoonWs.on("error", () =>
    logApi(session.api_key, chalk.red(`signal error on ${uuid.slice(0, 8)}`)),
  );
}

function auth(req, res, next) {
  const authHeader = req.headers["authorization"];
  const bearer =
    typeof authHeader === "string" && authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : undefined;
  const apiKey =
    req.headers["x-api-key"] ||
    req.body?.api_key ||
    req.query?.api_key ||
    bearer;
  if (!apiKey) return res.status(401).json({ error: "Missing API key." });
  const site = getSite(apiKey);
  if (!site) return res.status(401).json({ error: "Invalid API key." });
  if (!site.enabled)
    return res.status(403).json({ error: "API Key has been disabled." });
  req.site = site;
  req.apiKey = apiKey;
  next();
}

const app = express();

// CORS — browser clients rely on these headers and on OPTIONS preflight.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE",
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-Requested-With, Content-Type, Authorization, x-api-key",
  );
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  const ip = getClientIp(req);

  if (!checkIpLimit(ipLimits, ip, 60_000, 100)) {
    return res.status(429).json({
      error: "Too many requests from this IP. Try again in a minute.",
    });
  }

  // Only a request whose response has not started can be safely refused.
  // Writing a 408 after a handler has begun streaming (createSession's NDJSON)
  // throws ERR_HTTP_HEADERS_SENT and cuts the stream off mid-flight, which
  // truncates the response before the session uuid ever reaches the client.
  req.setTimeout(30_000, () => {
    if (res.headersSent) return;
    res.status(408).json({ error: "Request timeout." });
  });

  next();
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// The human side of the registration puzzle (see /cloud/v1/puzzles).
app.get("/puzzle", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "puzzle.html"));
});

app.get("/cloud/v1/config", (req, res) => {
  const enabledSites = Object.entries(sites.sites)
    .filter(([_, cfg]) => cfg.enabled)
    .map(([name, cfg]) => ({ name, api_key: cfg.api_key }));
  res.json({ sites: enabledSites });
});

app.get("/cloud/v1/embed", (req, res) => {
  if (!req.query.id) {
    return res.status(400).type("text").send("Missing `id` parameter");
  }
  res.sendFile(path.join(__dirname, "public", "e.html"));
});

app.get("/cloud/v1/embed-data", (req, res) => {
  const ip = getClientIp(req);
  if (!checkIpLimit(embedIpLimits, ip, 60_000, 30)) {
    return res.status(429).json({ error: "Too many requests. Slow down." });
  }

  const { id } = req.query;
  if (!id) return res.status(400).json({ error: "Missing id." });

  const session = sessions.get(id);
  if (!session)
    return res.status(404).json({ error: "Session not found or expired." });
  if (session.state !== "active")
    return res.status(400).json({ error: "Session not yet active." });

  res.json({
    ice_servers: session.embed_ice_servers,
    signaling_ws: session.embed_signaling_ws,
  });
});

// Human-in-the-loop registration puzzles. A puzzle blocks one account's
// creation until someone drags the slider: list to see what is waiting, then
// submit the offset. The waiting account flow relays it upstream and reports
// whether Raccoon accepted it.
app.get("/cloud/v1/puzzles", auth, (req, res) => {
  const now = Date.now();
  res.json({
    puzzles: [...pendingPuzzles.values()].map((p) => ({
      id: p.id,
      session: p.session,
      email: p.email,
      age_seconds: Math.floor((now - p.created_at) / 1000),
      expires_in_seconds: Math.max(
        0,
        Math.floor((PUZZLE_TIMEOUT_MS - (now - p.created_at)) / 1000),
      ),
      challenge: p.challenge,
    })),
  });
});

app.post("/cloud/v1/puzzles/:id", auth, async (req, res) => {
  const puzzle = pendingPuzzles.get(req.params.id);
  if (!puzzle)
    return res.status(404).json({ error: "Puzzle not found or expired." });

  const offset = Number(req.body?.offset);
  if (!Number.isInteger(offset) || offset < 0)
    return res.status(400).json({ error: "Invalid offset." });

  logApi(
    req.apiKey,
    `${chalk.gray("puzzle")} ${chalk.white(puzzle.id.slice(0, 8))} offset ${offset}`,
  );
  // Hand the answer to the account flow that is waiting on it, then wait for
  // Raccoon's own verdict so the solver learns whether the drag was right.
  puzzle.resolve(offset);
  const verdict = await puzzle.verdict;
  if (!verdict.ok)
    return res
      .status(422)
      .json({ error: `Raccoon rejected the solve: ${verdict.message}` });
  res.json({ status: "ok", message: verdict.message });
});

app.post("/cloud/v1/createSession", auth, async (req, res) => {
  const { game_key } = req.body;
  if (!game_key || typeof game_key !== "string" || game_key.length > 256) {
    return res.status(400).json({ error: "Invalid game_key." });
  }

  const { site, apiKey } = req;

  if (countActiveSessions(apiKey) >= site.max_concurrent_sessions) {
    return res.status(429).json({
      error: `Concurrent session limit reached (max ${site.max_concurrent_sessions}).`,
    });
  }

  const rl = checkRateLimit(apiKey, site);
  if (!rl.allowed)
    return res
      .status(429)
      .json({ error: `Rate limit exceeded: ${rl.reason}.` });

  if (!acquireAccountSlot(apiKey, site)) {
    return res
      .status(429)
      .json({ error: "Too many sessions being created. Try again shortly." });
  }

  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-cache");
  // Registering the account and joining the upstream queue legitimately takes
  // far longer than the 30s socket timeout applied to ordinary requests, and
  // this response is a long-lived stream that ends with the handler. Opt out
  // here; a session stuck in `creating` is still reaped after 5 minutes.
  req.setTimeout(0);
  res.flushHeaders();

  const push = (obj) => res.write(JSON.stringify(obj) + "\n");
  const uuid = randomUUID();

  const rawLimit = site.max_session_seconds ?? MAX_SESSION_SECONDS;
  const sessionLimit = Math.min(rawLimit, MAX_SESSION_SECONDS);

  const session = {
    uuid,
    api_key: apiKey,
    state: "creating",
    game_key,
    sn: "",
    token: "",
    created_at: Date.now(),
    max_session_seconds: sessionLimit,
    last_queue_poll_at: null,
    last_ping_at: null,
    puzzle_raised_at: null,
    startgame_timeout: null,
    queue_abandon_timeout: null,
    ping_timeout: null,
    session_timeout: null,
    raccoonWs: null,
    raccoonPingInterval: null,
    clientWs: null,
    costInterval: null,
  };
  sessions.set(uuid, session);
  logApi(
    apiKey,
    `${chalk.gray("createSession")} ${chalk.white(game_key)} → ${chalk.white(uuid.slice(0, 8))}`,
  );

  try {
    push({ status: "creating_account" });
    const acc = await createAccount({
      sessionUuid: uuid,
      onPuzzle: (entry) => {
        // A human is on the clock now, so the reaper grants this session the
        // puzzle window on top of its ordinary creation budget.
        session.puzzle_raised_at = Date.now();
        push({
          status: "puzzle_required",
          uuid,
          solve_within_seconds: Math.floor(PUZZLE_TIMEOUT_MS / 1000),
          puzzle: {
            id: entry.id,
            email: entry.email,
            challenge: entry.challenge,
          },
          submit_to: `/cloud/v1/puzzles/${entry.id}`,
        });
      },
    });

    releaseAccountSlot(apiKey);

    if (!sessions.has(uuid)) return res.end();

    session.sn = acc.sn;
    session.token = acc.token;
    recordUsage(apiKey);

    push({ status: "account_ready" });
    push({ status: "requesting_game" });

    const init = await doInitGame(session);

    if (!sessions.has(uuid)) return res.end();

    if (init.queued) {
      session.state = "queued";
      session.queue_id = init.queue_id;

      session.queue_abandon_timeout = setTimeout(
        () => killSession(uuid, "queue_abandoned"),
        60_000,
      );

      push({ status: "queue", uuid, queue_pos: init.initial_pos });
    } else {
      applyServerData(session, init.server_data);
      session.state = "finished_queue";
      session.finished_queue_at = Date.now();

      session.startgame_timeout = setTimeout(
        () => killSession(uuid, "startgame_timeout"),
        30_000,
      );

      push({
        status: "finished_queue",
        uuid,
        fetch_this_within_30s_or_terminate: "/cloud/v1/startGame",
      });
    }
  } catch (e) {
    releaseAccountSlot(apiKey);
    push({ status: "error", error: e.message });
    killSession(uuid, "creation_error");
  }

  res.end();
});

app.get("/cloud/v1/getQueue", auth, async (req, res) => {
  const { uuid } = req.query;
  if (!uuid) return res.status(400).json({ error: "Missing uuid." });

  const session = sessions.get(uuid);
  if (!session)
    return res.status(404).json({ error: "Session not found or expired." });
  if (session.api_key !== req.apiKey)
    return res.status(403).json({ error: "Forbidden." });

  if (session.state !== "queued" && session.state !== "finished_queue") {
    return res
      .status(400)
      .json({ error: `Session is '${session.state}', not pollable.` });
  }

  const now = Date.now();
  if (session.last_queue_poll_at && now - session.last_queue_poll_at < 3_000) {
    return res
      .status(429)
      .json({ error: "Too fast. Poll getQueue at most once every 3 seconds." });
  }
  session.last_queue_poll_at = now;

  clearTimeout(session.queue_abandon_timeout);
  session.queue_abandon_timeout = setTimeout(
    () => killSession(uuid, "queue_abandoned"),
    60_000,
  );

  if (session.state === "finished_queue") {
    return res.json({
      status: "finished_queue",
      uuid,
      fetch_this_within_30s_or_terminate: "/cloud/v1/startGame",
    });
  }

  try {
    const pos = await doPollQueue(session, session.queue_id);

    if (pos === 0) {
      const serverData = await doClaimGame(session, session.queue_id);
      applyServerData(session, serverData);
      session.state = "finished_queue";
      session.finished_queue_at = Date.now();
      clearTimeout(session.queue_abandon_timeout);

      session.startgame_timeout = setTimeout(
        () => killSession(uuid, "startgame_timeout"),
        30_000,
      );

      return res.json({
        status: "finished_queue",
        uuid,
        fetch_this_within_30s_or_terminate: "/cloud/v1/startGame",
      });
    }

    return res.json({ status: "queue", queue_pos: pos });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

app.post("/cloud/v1/startGame", auth, (req, res) => {
  const { uuid } = req.body;
  if (!uuid) return res.status(400).json({ error: "Missing uuid." });

  const session = sessions.get(uuid);
  if (!session)
    return res.status(404).json({ error: "Session not found or expired." });
  if (session.api_key !== req.apiKey)
    return res.status(403).json({ error: "Forbidden." });
  if (session.state !== "finished_queue") {
    return res
      .status(400)
      .json({ error: `Session is '${session.state}', not ready to start.` });
  }

  clearTimeout(session.startgame_timeout);
  clearTimeout(session.queue_abandon_timeout);

  session.state = "active";
  session.game_started_at = Date.now();

  resetPingTimeout(uuid);

  session.session_timeout = setTimeout(
    () => killSession(uuid, "max_session_length"),
    session.max_session_seconds * 1000,
  );

  const iceServers = [
    { urls: "stun:stun.l.google.com:19302" },
    ...(session.turns || []).map((t) => ({
      urls: t.turn_url,
      username: t.turn_user,
      credential: t.turn_password,
    })),
  ];

  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const signalingWs = `${proto === "https" ? "wss" : "ws"}://${req.headers.host}/cloud/v1/signal/${uuid}`;

  session.embed_ice_servers = iceServers;
  session.embed_signaling_ws = signalingWs;

  session.costInterval = setInterval(() => doCost(session), 25_000);

  res.json({
    ice_servers: iceServers,
    signaling_ws: signalingWs,
    max_seconds: session.max_session_seconds,
  });

  logApi(
    req.apiKey,
    `${chalk.gray("startGame")} ${chalk.white(session.game_key)} → ${chalk.white(uuid.slice(0, 8))}`,
  );

  connectRaccoonSignaling(session);
});

app.post("/cloud/v1/pingSession", auth, (req, res) => {
  const { uuid } = req.body;
  if (!uuid) return res.status(400).json({ error: "Missing uuid." });

  const session = sessions.get(uuid);
  if (!session)
    return res.status(404).json({ error: "Session not found or expired." });
  if (session.api_key !== req.apiKey)
    return res.status(403).json({ error: "Forbidden." });
  if (session.state !== "active")
    return res.status(400).json({ error: "Session is not active." });

  const now = Date.now();
  if (session.last_ping_at && now - session.last_ping_at < 3_000) {
    return res
      .status(429)
      .json({ error: "Too fast. Ping at most once every 3 seconds." });
  }

  session.last_ping_at = now;
  resetPingTimeout(uuid);

  const { site } = req;
  const usage = getUsageStats(req.apiKey);
  const timeUsed = Math.floor((now - session.game_started_at) / 1000);

  res.json({
    session_time_used_seconds: timeUsed,
    session_time_limit_seconds: session.max_session_seconds,
    quota: {
      minute: { used: usage.perMin, limit: site.limits.per_minute },
      hour: { used: usage.perHour, limit: site.limits.per_hour },
      day: { used: usage.perDay, limit: site.limits.per_day },
      month: { used: usage.perMonth, limit: site.limits.per_month },
    },
  });
});

app.post("/cloud/v1/quitSession", auth, (req, res) => {
  const { uuid } = req.body;
  if (!uuid) return res.status(400).json({ error: "Missing uuid." });

  const session = sessions.get(uuid);
  if (!session)
    return res.status(404).json({ error: "Session not found or expired." });
  if (session.api_key !== req.apiKey)
    return res.status(403).json({ error: "Forbidden." });

  logApi(
    req.apiKey,
    `${chalk.gray("quitSession")} ${chalk.white(uuid.slice(0, 8))}`,
  );
  killSession(uuid, "quit_requested");
  res.json({ status: "ok" });
});

const httpServer = createServer(app);
const wss = new WebSocketServer({ noServer: true });

httpServer.on("upgrade", (req, socket, head) => {
  const match = req.url.match(/^\/cloud\/v1\/signal\/([0-9a-f-]{36})$/i);
  if (!match) {
    socket.destroy();
    return;
  }

  const uuid = match[1];
  const session = sessions.get(uuid);

  if (!session || session.state !== "active") {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    session.clientWs = ws;

    ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        return;
      }

      const rws = session.raccoonWs;
      if (!rws || rws.readyState !== WebSocket.OPEN) return;

      if (msg.type === "rtc_offer" && msg.sdp) {
        rws.send(
          JSON.stringify({
            id: "rtc_sdp",
            from: session.sn,
            to: session.gl_key,
            body: { sdp: msg.sdp, type: "offer" },
          }),
        );
      } else if (msg.type === "rtc_candidate" && msg.candidate) {
        rws.send(
          JSON.stringify({
            id: "rtc_sdp",
            from: session.sn,
            to: session.gl_key,
            body: { type: "candidate", sdp: msg.candidate },
          }),
        );
      }
    });

    ws.on("close", () => {
      session.clientWs = undefined;
    });
    ws.on("error", () => {});
  });
});

setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [ip, timestamps] of ipLimits.entries()) {
    const recent = timestamps.filter((t) => t > cutoff);
    if (recent.length === 0) ipLimits.delete(ip);
    else ipLimits.set(ip, recent);
  }
  for (const [ip, timestamps] of embedIpLimits.entries()) {
    const recent = timestamps.filter((t) => t > cutoff);
    if (recent.length === 0) embedIpLimits.delete(ip);
    else embedIpLimits.set(ip, recent);
  }
}, 60_000).unref?.();

httpServer.listen(PORT, () => {
  const label = (s) => chalk.dim(s.padStart(12));
  const siteList = Object.entries(sites.sites);

  console.log("");
  console.log(chalk.bold(" ⚡ Plutonium-CGAPI"));
  console.log("");
  console.log(label("port") + "  " + chalk.white(PORT));
  console.log(label("sites") + "  " + chalk.white(siteList.length));
  console.log(
    label("cap") +
      "  " +
      chalk.white(`${MAX_SESSION_SECONDS / 60}m max session`),
  );
  console.log(label("pool") + "  " + chalk.white(`${POOL_TARGET} accounts`));
  console.log("");

  siteList.forEach(([name, cfg]) => {
    const sessionCap = Math.min(
      cfg.max_session_seconds ?? MAX_SESSION_SECONDS,
      MAX_SESSION_SECONDS,
    );
    const status = cfg.enabled ? chalk.green("enabled") : chalk.red("disabled");
    console.log(
      `  ${chalk.white(name.padEnd(20))} ${status}  ${chalk.blackBright(`max ${cfg.max_concurrent_sessions} concurrent  ·  ${sessionCap}s limit`)}`,
    );
  });

  console.log("");

  fillPool().catch(() => {});
});
