// socks.js - minimal SOCKS5 server (CONNECT only, username/password auth, no dependencies)
import net from "node:net";
import dns from "node:dns/promises";
import http from "node:http";
import crypto from "node:crypto";

const SOCKS_PORT = Number(process.env.SOCKS_PORT || 1080);
const HTTP_PORT = Number(process.env.PORT || 8080); // only for the platform health check
const USER = process.env.PROXY_USER;
const PASS = process.env.PROXY_PASS;

if (!USER || !PASS) {
  console.error("Set PROXY_USER and PROXY_PASS environment variables.");
  process.exit(1);
}

const digest = (s) => crypto.createHash("sha256").update(s).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(digest(a), digest(b));

// Refuse loopback / private / link-local targets so the proxy cannot reach Sevalla's internal network
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const v6 = ip.toLowerCase();
  if (v6.startsWith("::ffff:")) return isPrivate(v6.slice(7));
  return v6 === "::1" || v6 === "::" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe80");
}

function handle(client) {
  let buf = Buffer.alloc(0);
  let stage = 0; // 0 greeting, 1 auth, 2 request, 3 connecting/piping

  client.setNoDelay(true);
  client.setTimeout(30000, () => client.destroy());
  client.on("error", () => client.destroy());

  const reply = (code) => client.end(Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]));

  function onData(chunk) {
    buf = Buffer.concat([buf, chunk]);

    for (;;) {
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5) return client.destroy();
        const n = buf[1];
        if (buf.length < 2 + n) return;
        const methods = buf.subarray(2, 2 + n);
        buf = buf.subarray(2 + n);
        if (!methods.includes(2)) return void client.end(Buffer.from([5, 0xff]));
        client.write(Buffer.from([5, 2]));
        stage = 1;
      } else if (stage === 1) {
        if (buf.length < 2) return;
        const ul = buf[1];
        if (buf.length < 3 + ul) return;
        const pl = buf[2 + ul];
        if (buf.length < 3 + ul + pl) return;
        const u = buf.subarray(2, 2 + ul).toString();
        const p = buf.subarray(3 + ul, 3 + ul + pl).toString();
        buf = buf.subarray(3 + ul + pl);
        if (!safeEq(u, USER) || !safeEq(p, PASS)) return void client.end(Buffer.from([1, 1]));
        client.write(Buffer.from([1, 0]));
        stage = 2;
      } else if (stage === 2) {
        if (buf.length < 4) return;
        if (buf[0] !== 5 || buf[1] !== 1) return reply(7); // only CONNECT
        const atyp = buf[3];
        let host, off;
        if (atyp === 1) {
          if (buf.length < 10) return;
          host = [...buf.subarray(4, 8)].join(".");
          off = 8;
        } else if (atyp === 3) {
          if (buf.length < 5) return;
          const l = buf[4];
          if (buf.length < 7 + l) return;
          host = buf.subarray(5, 5 + l).toString();
          off = 5 + l;
        } else if (atyp === 4) {
          if (buf.length < 22) return;
          const parts = [];
          for (let i = 0; i < 8; i++) parts.push(buf.readUInt16BE(4 + i * 2).toString(16));
          host = parts.join(":");
          off = 20;
        } else {
          return reply(8);
        }
        const port = buf.readUInt16BE(off);
        const rest = buf.subarray(off + 2);
        buf = Buffer.alloc(0);
        stage = 3;
        client.off("data", onData);
        client.pause();
        connect(host, port, rest);
        return;
      } else {
        return;
      }
    }
  }

  async function connect(host, port, rest) {
    let addr = host;
    try {
      if (!net.isIP(host)) addr = (await dns.lookup(host)).address;
    } catch {
      return reply(4); // host unreachable
    }
    if (isPrivate(addr)) return reply(2); // not allowed by ruleset

    let connected = false;
    const remote = net.connect(port, addr, () => {
      connected = true;
      client.setTimeout(0);
      client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      if (rest.length) remote.write(rest);
      client.pipe(remote);
      remote.pipe(client);
      client.resume();
    });
    remote.setNoDelay(true);
    remote.on("error", () => {
      if (!connected) reply(5); // connection refused
      client.destroy();
    });
    remote.on("close", () => client.destroy());
    client.on("close", () => remote.destroy());
  }

  client.on("data", onData);
}

net.createServer(handle).listen(SOCKS_PORT, () => {
  console.log(`SOCKS5 listening on port ${SOCKS_PORT}`);
});

// Plain HTTP responder so the platform sees the app as healthy
http.createServer((req, res) => res.end("ok")).listen(HTTP_PORT);
