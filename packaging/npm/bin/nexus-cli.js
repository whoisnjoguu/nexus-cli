#!/usr/bin/env node
// Thin launcher: ensures the platform binary is present, then execs nexus-cli with the given args.
"use strict";

const { spawn } = require("child_process");
const { ensureBinary } = require("../lib/install.js");

(async () => {
    try {
        const bin = await ensureBinary();
        const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
        child.on("exit", (code, signal) => {
            if (signal) process.kill(process.pid, signal);
            else process.exit(code === null ? 0 : code);
        });
        child.on("error", (err) => {
            process.stderr.write(`nexus-cli: ${err.message}\n`);
            process.exit(1);
        });
    } catch (err) {
        process.stderr.write(`nexus-cli: ${err.message}\n`);
        process.exit(1);
    }
})();
