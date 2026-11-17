#!/usr/bin/env node
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
const globalModules = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
const require = createRequire(join(globalModules, "@earendil-works/pi-coding-agent/package.json"));
const entry = join(globalModules, "@earendil-works/pi-coding-agent/dist/index.js");
const { createReadTool } = await import(pathToFileURL(entry));
const nativeMime = await import(pathToFileURL(join(dirname(entry), "utils/mime.js")));
const { createJiti } = require("jiti");
process.env.PI_SANDBOX_BIN = process.env.PI_SANDBOX_BIN || join(root, "target/debug/pi-sandbox");
const jiti = createJiti(import.meta.url, {
    alias: { "@earendil-works/pi-coding-agent": entry },
});
const { detectSupportedImageMimeType } = await jiti.import(join(root, "pi-extension/image-mime.ts"));
const extension = await jiti.import(join(root, "pi-extension/index.ts"), { default: true });
const tools = new Map();
const commands = new Map();
extension({
    registerFlag() {},
    registerCommand(name, command) { commands.set(name, command); },
    registerTool(tool) { tools.set(tool.name, tool); },
    on() {},
});
const cwd = mkdtempSync(join(tmpdir(), "pi-sandbox-image-"));
const ctx = {
    cwd,
    model: { input: ["text", "image"] },
    ui: { notify() {}, setStatus() {} },
};
const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aD1sAAAAASUVORK5CYII=",
    "base64",
);
const fixtures = [
    png, Buffer.from("GIF87a"), Buffer.from("GIF89a"), Buffer.from("RIFF1234WEBP"),
    Buffer.from([255, 216, 255, 247]), Buffer.from("BM"), Buffer.alloc(0),
];
for (const bytes of fixtures) {
    assert.equal(detectSupportedImageMimeType(bytes), nativeMime.detectSupportedImageMimeType(bytes));
}
// Check signature parsing and short/malformed inputs against the installed native detector.
for (let size = 0; size < 150; size++) {
    for (const bytes of fixtures) {
        const candidate = Buffer.alloc(size);
        bytes.copy(candidate);
        assert.equal(detectSupportedImageMimeType(candidate), nativeMime.detectSupportedImageMimeType(candidate));
    }
}
try {
    writeFileSync(join(cwd, "image.data"), png);
    const { PhotonImage } = require("@silvia-odwyer/photon-node");
    const largeImage = new PhotonImage(new Uint8Array(8 * 4 * 4).fill(255), 8, 4);
    writeFileSync(join(cwd, "resize.png"), largeImage.get_bytes());
    largeImage.free();
    writeFileSync(join(cwd, "fallback"), "BMthis is actually text\nsecond line");
    writeFileSync(join(cwd, "nul"), Buffer.from("text\0data"));
    writeFileSync(join(cwd, "large.log"), "hello world\n".repeat(100_000));
    const native = createReadTool(cwd);
    for (const fs of ["readonly", "write", "unrestricted"]) {
        for (const net of ["none", "restricted", "unrestricted"]) {
            await commands.get("fs").handler(fs, ctx);
            await commands.get("net").handler(net, ctx);
            for (const input of ["image", "text"]) {
                ctx.model = {
                    input: [input],
                    inputLimits: { images: { resize: { maxWidth: 2, maxHeight: 2 } } },
                };
                for (const params of [
                    { path: "image.data" },
                    { path: "resize.png" },
                    { path: "fallback", offset: 2, limit: 1 },
                    { path: "nul" },
                ]) {
                    const expected = await native.execute("native", params, undefined, undefined, ctx);
                    const actual = await tools.get("read").execute("sandbox", params, undefined, undefined, ctx);
                    if (params.path === "resize.png") {
                        assert.match(actual.content[0].text, /8x4/);
                        assert.equal(actual.content[1].type, "image");
                    }
                    assert.deepEqual(actual, expected, `${fs}/${net}/${input}/${params.path}`);
                }
            }
            const text = await tools.get("read").execute(
                "text", { path: "large.log", limit: 2 }, undefined, undefined, ctx,
            );
            assert.ok(text.content[0].text.startsWith("hello world\nhello world"));
            assert.ok(JSON.stringify(text).length < 1024);
        }
    }
    await commands.get("fs").handler("readonly", ctx);
    await assert.rejects(
        tools.get("read").execute("error", { path: "missing" }, undefined, undefined, ctx),
        /failed to read/,
    );
    console.log("PASS detector parity and native read parity across all 9 sandbox modes, text bounds, and errors");
} finally {
    rmSync(cwd, { recursive: true, force: true });
}
