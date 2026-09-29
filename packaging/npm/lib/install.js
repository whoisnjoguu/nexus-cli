// Resolves and lazily downloads the nexus-cli release binary for the current platform.
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const { execFileSync } = require("child_process");

const REPO = "whoisnjoguu/nexus-cli";

// target maps the Node platform/arch to the goreleaser archive naming.
function target() {
    const platMap = { darwin: "darwin", linux: "linux", win32: "windows" };
    const archMap = { x64: "amd64", arm64: "arm64" };
    const o = platMap[process.platform];
    const a = archMap[process.arch];
    if (!o || !a) {
        throw new Error(`unsupported platform: ${process.platform}/${process.arch}`);
    }
    const windows = o === "windows";
    return {
        os: o,
        arch: a,
        ext: windows ? "zip" : "tar.gz",
        bin: windows ? "nexus-cli.exe" : "nexus-cli",
    };
}

// download fetches url to dest, following GitHub's redirect to the asset store.
function download(url, dest) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { headers: { "User-Agent": "nexus-cli-npm" } }, (res) => {
            if ([301, 302, 307, 308].includes(res.statusCode)) {
                res.resume();
                return download(res.headers.location, dest).then(resolve, reject);
            }
            if (res.statusCode !== 200) {
                res.resume();
                return reject(new Error(`download failed (${res.statusCode}): ${url}`));
            }
            const file = fs.createWriteStream(dest);
            res.pipe(file);
            file.on("finish", () => file.close(() => resolve()));
            file.on("error", reject);
        });
        req.on("error", reject);
    });
}

function vendorDir() {
    return path.join(__dirname, "..", "vendor");
}

// ensureBinary returns the path to the platform binary, downloading + extracting it on first use.
async function ensureBinary() {
    const { os: o, arch, ext, bin } = target();
    const dest = path.join(vendorDir(), bin);
    if (fs.existsSync(dest)) {
        return dest;
    }

    const version = require("../package.json").version;
    const tag = "v" + version;
    const archive = `nexus-cli_${version}_${o}_${arch}.${ext}`;
    const url = `https://github.com/${REPO}/releases/download/${tag}/${archive}`;

    fs.mkdirSync(vendorDir(), { recursive: true });
    const tmp = path.join(os.tmpdir(), `${Date.now()}-${archive}`);
    process.stderr.write(`nexus-cli: fetching ${tag} for ${o}/${arch}…\n`);
    await download(url, tmp);

    // System tar handles .tar.gz everywhere and .zip on Windows 10+ (bsdtar).
    execFileSync("tar", ["-xf", tmp, "-C", vendorDir()], { stdio: "inherit" });
    fs.rmSync(tmp, { force: true });

    if (!fs.existsSync(dest)) {
        throw new Error("binary not found in archive after extraction");
    }
    fs.chmodSync(dest, 0o755);
    return dest;
}

module.exports = { ensureBinary };
