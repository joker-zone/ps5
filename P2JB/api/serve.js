#!/usr/bin/env node
/* Standalone host for the whole site, including the api/payload/<name> endpoint.
 *
 *     node api/serve.js [port]        (run it from the site root; default port 8080)
 *     PS5_ALLOWED_ORIGINS=http://host:8080 (comma-separated page origins)
 *
 * Why this exists: the ELF tile menu cannot deliver a payload from the browser -
 * JavaScript has no raw sockets, and an HTTP POST straight to port 9021 would
 * prepend HTTP headers so elfldr would not see \x7fELF at offset 0. The page asks
 * the server to make the TCP connection instead.
 *
 * The console is the one making the request, so its address is the socket's own
 * remote address. Nothing to configure.
 *
 * Static files are served relative to the directory you run this from, so hosting
 * under a subdirectory works the same way as at a root.
 */
"use strict";
const http = require("http"), net = require("net"), fs = require("fs"),
    path = require("path");

const ROOT = process.cwd();
const PORT = parseInt(process.argv[2] || "8080", 10);
const ELFLDR_PORT = 9021;
const ALLOWED_ORIGINS = new Set(
    (process.env.PS5_ALLOWED_ORIGINS || "").split(",").map(normalizeOrigin).filter(Boolean)
);

const MIME = {
    ".html": "text/html; charset=utf-8", ".js": "application/javascript",
    ".css": "text/css", ".png": "image/png", ".gif": "image/gif",
    ".jpg": "image/jpeg", ".json": "application/json",
    ".elf": "application/octet-stream", ".bin": "application/octet-stream",
    ".txt": "text/plain; charset=utf-8"
};

function normalizeOrigin(value) {
    try {
        const parsed = new URL(value.trim());
        if ((parsed.protocol !== "http:" && parsed.protocol !== "https:")
            || parsed.username || parsed.password || parsed.pathname !== "/"
            || parsed.search || parsed.hash) return "";
        return parsed.origin;
    } catch (_) {
        return "";
    }
}

function isWithin(root, candidate) {
    const relative = path.relative(root, candidate);
    return relative !== "" && relative !== ".."
        && !relative.startsWith(".." + path.sep) && !path.isAbsolute(relative);
}

function resolveInside(root, candidate, cb) {
    fs.realpath(root, (rootErr, realRoot) => {
        if (rootErr) return cb(rootErr);
        fs.realpath(candidate, (fileErr, realFile) => {
            if (fileErr) return cb(fileErr);
            if (!isWithin(realRoot, realFile)) {
                const error = new Error("path outside allowed directory");
                error.code = "EACCES";
                return cb(error);
            }
            cb(null, realFile);
        });
    });
}

function sendPayload(name, ip, cb) {
    if (!/^[A-Za-z0-9._-]+\.(elf|bin)$/.test(name)) return cb(new Error("bad payload name"));
    const payloadRoot = path.join(ROOT, "payloads");
    resolveInside(ROOT, payloadRoot, (rootErr, realPayloadRoot) => {
        if (rootErr) return cb(new Error("payload directory unavailable"));
        const file = path.join(realPayloadRoot, name);
        resolveInside(realPayloadRoot, file, (pathErr, realFile) => {
            if (pathErr) return cb(new Error("payload not found: " + name));
            fs.readFile(realFile, (err, buf) => {
                if (err) return cb(new Error("payload not found: " + name));
                const sock = net.connect(ELFLDR_PORT, ip);
                let done = false;
                const finish = (e) => { if (!done) { done = true; sock.destroy(); cb(e, buf.length); } };
                sock.setTimeout(15000, () => finish(new Error("timeout talking to " + ip)));
                sock.on("error", (e) => finish(new Error("connect " + ip + ":" + ELFLDR_PORT + " - " + e.message)));
                sock.on("connect", () => sock.end(buf, () => finish(null)));
            });
        });
    });
}

http.createServer((req, res) => {
    let p;
    try {
        p = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    } catch (_) {
        res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        return res.end("bad request");
    }
    const m = p.match(/\/api\/payload\/([^/]+)$/);

    if (m) {
        if (req.method !== "POST") {
            res.writeHead(405, { "Allow": "POST", "Content-Type": "application/json" });
            return res.end(JSON.stringify({ ok: false, error: "method not allowed" }));
        }
        const requestOrigin = normalizeOrigin(req.headers.origin || "");
        if (!requestOrigin || !ALLOWED_ORIGINS.has(requestOrigin)) {
            res.writeHead(403, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ ok: false, error: "origin not allowed" }));
        }
        let ip = req.socket.remoteAddress || "";
        if (ip.startsWith("::ffff:")) ip = ip.slice(7);          // IPv4-mapped IPv6
        sendPayload(m[1], ip, (err, bytes) => {
            res.writeHead(err ? 502 : 200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(err
                ? { ok: false, error: err.message }
                : { ok: true, bytes, name: m[1], to: ip + ":" + ELFLDR_PORT }));
            console.log(`[payload] ${m[1]} -> ${ip}  ${err ? "FAILED: " + err.message : bytes + " bytes"}`);
        });
        return;
    }

    // the site's own beacons; answer them so they do not 404-spam the log
    if (p.indexOf("/log/") >= 0) { res.writeHead(204); return res.end(); }

    let file = path.resolve(ROOT, "." + p);
    if (p.endsWith("/")) file = path.join(file, "index.html");
    resolveInside(ROOT, file, (pathErr, realFile) => {
        if (pathErr) {
            const status = pathErr.code === "EACCES" ? 403 : 404;
            res.writeHead(status);
            if (status === 404) console.log("[404] " + p);
            return res.end(status === 403 ? "forbidden" : "not found");
        }
        fs.readFile(realFile, (err, buf) => {
            if (err) { res.writeHead(404); console.log("[404] " + p); return res.end("not found"); }
            res.writeHead(200, { "Content-Type": MIME[path.extname(realFile).toLowerCase()] || "application/octet-stream" });
            res.end(buf);
        });
    });
}).listen(PORT, () => {
    console.log(`serving ${ROOT} on port ${PORT}`);
    console.log(`api/payload/<name> will connect back to the requesting console on :${ELFLDR_PORT}`);
    console.log("Set PS5_ALLOWED_ORIGINS to the exact origin(s) serving the page.");
});
