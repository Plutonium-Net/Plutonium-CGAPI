import { expect, test } from 'bun:test';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const repoRoot = path.resolve(import.meta.dir);
const apiFile = path.join(repoRoot, 'api', 'api.js').split(path.sep).join('/');

// The retry loop only exists to survive outcomes that need a *different*
// address, and those outcomes can only be produced by Raccoon and malq after a
// human solves a puzzle. So the probe stubs both upstreams and drives the real
// /cloud/v1/createSession stream: attempt 1's address is refused the way Raccoon
// refuses a disposable domain, and the test asserts a second address is
// requested, solved and used to reach the queue.
const probe = `
const PORT = process.env.PORT;
const API = "http://127.0.0.1:" + PORT;
const realFetch = globalThis.fetch;

// Three addresses, one per reason a different address is worth trying, with the
// working one last because a success ends the flow: 1 Raccoon refuses it,
// 2 its provider cannot be read at all, 3 works (after register asks for a new
// code, which is the third reason). All three have real MX records, which the
// pre-screen checks before spending a solve.
const DOMAINS = ["gmail.com", "securamail.org", "protonmail.com"];
const emailFor = (n) => "attempt" + n + "@" + (DOMAINS[n - 1] || "example.com");
let sessionsServed = 0;
const calls = [];
// Raccoon refuses sendEmail until that address has been through the puzzle, so
// the stub tracks which addresses have solved one - that is what makes the
// second attempt need its own solve rather than reusing the first. A solve is
// single-use, so register demanding "a new email code" costs another puzzle.
const solvedPuzzles = new Set();
const CODE_POOL = ["654321", "111222", "333444"];
const codesByEmail = new Map();
let registerCalls = 0;

const json = (body, status, headers) =>
  new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { "content-type": "application/json", ...(headers || {}) },
  });

globalThis.fetch = async (url, opts) => {
  const u = String(url);
  // The probe's own calls to the API under test must reach the real server;
  // everything else (Raccoon, and malq on :4400) is stubbed by path.
  if (u.startsWith(API)) return realFetch(url, opts);
  const p = new URL(u).pathname;

  if (p === "/api/v1/session") {
    sessionsServed += 1;
    return json({
      address: emailFor(sessionsServed),
      token: "tok" + sessionsServed,
      provider: "stub",
    });
  }
  if (p.startsWith("/api/v1/inbox/")) {
    const token = p.split("/").pop();
    if (token === "tok2") {
      // The second address sits on a provider whose scraper throws on every
      // poll, which is what "mailbox errors" means in a real run.
      return json({ error: "provider scrape failed: .map is not a function" }, 500);
    }
    const codes = codesByEmail.get(emailFor(Number(token.slice(3)))) || [];
    // Every email Raccoon sent to this address stays in the inbox, including
    // the stale one from a previous register attempt.
    return json({
      mail: codes.map((c) => ({
        subject: "RaccoonGame Account Registration Verification",
        body: "Your verification code is " + c,
      })),
    });
  }
  if (p === "/users/emailRegisterCaptcha") {
    return json({
      status: 200,
      data: {
        challenge_id: "ch" + sessionsServed,
        background: "data:,",
        piece: "data:,",
        width: 300,
        height: 150,
        piece_size: 50,
        piece_y: 60,
      },
    });
  }
  if (p === "/users/emailRegisterCaptchaVerify") {
    const body = String((opts && opts.body) || "");
    const m = body.match(/email=([^&]*)/);
    if (m) solvedPuzzles.add(decodeURIComponent(m[1]));
    return json({ status: 200 });
  }
  if (p === "/users/sendEmail") {
    const body = String((opts && opts.body) || "");
    const m = body.match(/email=([^&]*)/);
    const email = m ? decodeURIComponent(m[1]) : "?";
    calls.push("sendEmail:" + email);
    // Raccoon's gate: no mail until this address has passed its puzzle.
    if (!solvedPuzzles.has(email))
      return json({ status: 400, msg: "Please complete the puzzle verification." });
    solvedPuzzles.delete(email); // the verification authorises one send
    // And what it answers for a domain on its disposable list: HTTP 200, but
    // the body refuses it.
    if (email === emailFor(1))
      return json({ status: 400, msg: "Temporary email addresses are not supported." });
    const codes = codesByEmail.get(email) || [];
    codes.push(CODE_POOL[codes.length % CODE_POOL.length]);
    codesByEmail.set(email, codes);
    return json({ status: 200 });
  }
  if (p === "/users/emailRegister") {
    const body = String((opts && opts.body) || "");
    const m = body.match(/email=([^&]*)/);
    const email = m ? decodeURIComponent(m[1]) : "?";
    registerCalls += 1;
    calls.push("emailRegister:" + email);
    // The refusal that ended the last live attempt, from Raccoon itself.
    if (email === emailFor(3) && registerCalls === 1)
      return json({
        status: 400,
        msg: "Human verification is required. Please request a new email code.",
      });
    return json({ status: 200 });
  }
  if (p === "/users/emailLogin")
    return json({ status: 200, data: { user_token: "utok" } }, 200, {
      "set-cookie": "as_user_token=utok; Path=/",
    });
  if (p === "/userGame/checkCost") return json({ status: 200 });
  if (p === "/jyapi/playGame")
    return json({ status: 201, data: { play_queue_id: "q1", queue_pos: 1 } });
  return json({ status: 200 });
};

(async () => {
  require(process.env.API_FILE);
  await Bun.sleep(700);
  const cfg = await realFetch(API + "/cloud/v1/config").then((r) => r.json());
  const key = cfg.sites[0].api_key;
  const res = await realFetch(API + "/cloud/v1/createSession", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": key },
    body: JSON.stringify({ game_key: "test-game" }),
  });
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const out = { puzzles: [], statuses: [], error: null, calls, sessionsServed: 0 };
  const deadline = Date.now() + 90_000;
  const finish = () => {
    out.sessionsServed = sessionsServed;
    console.log("PROBE " + JSON.stringify(out));
    process.exit(0);
  };
  while (Date.now() < deadline) {
    const { value, done: ended } = await reader.read();
    if (ended) break;
    buf += dec.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf("\\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let evt;
      try {
        evt = JSON.parse(line);
      } catch {
        continue;
      }
      out.statuses.push(evt.status);
      if (evt.status === "puzzle_required") {
        out.puzzles.push({
          attempt: evt.attempt,
          attempts: evt.attempts,
          email: evt.puzzle && evt.puzzle.email,
        });
        await realFetch(API + evt.submit_to, {
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": key },
          body: JSON.stringify({ offset: 137 }),
        });
      }
      if (evt.error) out.error = evt.error;
    }
    if (
      out.error ||
      out.statuses.includes("queue") ||
      out.statuses.includes("finished_queue")
    )
      finish();
  }
  finish();
})();
`;

test(
  "a refused address, an unreadable mailbox and a register demanding a new code are all retried",
  async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'plutonium-mail-retry-'));
    const probeFile = path.join(dir, 'probe.cjs');
    const listFile = path.join(dir, 'disposable.txt');
    fs.writeFileSync(probeFile, probe);
    // Keeps the disposable-domain check offline and deterministic.
    fs.writeFileSync(listFile, 'blocked.invalid\n');

    const child = spawn(process.execPath, [probeFile], {
      cwd: path.join(repoRoot, 'api'),
      env: {
        ...process.env,
        PORT: '3917',
        MAIL_ATTEMPTS: '3',
        // Keeps a provider that never answers from making this test wait the
        // full production window (four addresses would otherwise take ~8min).
        MAIL_WAIT_SECONDS: '6',
        POOL_TARGET: '0',
        DISPOSABLE_LIST_FILE: listFile,
        API_FILE: apiFile,
      },
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (c) => stdout.push(c));
    child.stderr.on('data', (c) => stderr.push(c));
    const code = await new Promise((resolve) => child.on('close', resolve));
    const out = Buffer.concat(stdout).toString();
    const err = Buffer.concat(stderr).toString();

    const line = out.split('\n').find((l) => l.startsWith('PROBE '));
    expect(line, `no probe line.\nstdout:\n${out}\nstderr:\n${err}`).toBeTruthy();
    const result = JSON.parse(line!.slice('PROBE '.length));

    expect(code).toBe(0);
    // One solve per sendEmail, which is what a launch costs a human: address 1
    // once (refused), address 2 once (mailbox unreadable), address 3 twice
    // (register demanded a new code).
    expect(result.puzzles.map((p: any) => [p.attempt, p.attempts, p.email])).toEqual([
      [1, 3, 'attempt1@gmail.com'],
      [2, 3, 'attempt2@securamail.org'],
      [3, 3, 'attempt3@protonmail.com'],
      [3, 3, 'attempt3@protonmail.com'],
    ]);
    // Per cycle: sendEmail refused for want of a puzzle, solve, sendEmail again
    // for the real verdict. Address 1 is refused as disposable, address 2 never
    // answers at all, and address 3 registers twice because the first register
    // demanded a new code.
    expect(result.calls).toEqual([
      'sendEmail:attempt1@gmail.com',
      'sendEmail:attempt1@gmail.com',
      'sendEmail:attempt2@securamail.org',
      'sendEmail:attempt2@securamail.org',
      'sendEmail:attempt3@protonmail.com',
      'sendEmail:attempt3@protonmail.com',
      'emailRegister:attempt3@protonmail.com',
      'sendEmail:attempt3@protonmail.com',
      'sendEmail:attempt3@protonmail.com',
      'emailRegister:attempt3@protonmail.com',
    ]);
    expect(result.error).toBeNull();
    expect(result.statuses).toContain('account_ready');
    expect(result.statuses[result.statuses.length - 1]).toBe('queue');
  },
  120_000,
);
