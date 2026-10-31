// Network-attempt proof guard | Chibitek Engineering | 2026-10-18
// Run via node --import ./scripts/network-guard.mjs dist/server.js --root ...
// Instrumentation complements OS network denial; it is not a security sandbox.
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import { syncBuiltinESMExports } from 'node:module';
let attempts = 0;
function deny() { attempts++; throw new Error('Network call prohibited by proof guard'); }
net.Socket.prototype.connect = deny;
net.Server.prototype.listen = deny;
dgram.createSocket = deny;
http.request = http.get = https.request = https.get = deny;
for (const key of Object.keys(dns)) if (key === 'lookup' || key.startsWith('resolve')) dns[key] = deny;
for (const key of Object.keys(dns.promises)) if (key === 'lookup' || key.startsWith('resolve')) dns.promises[key] = deny;
globalThis.fetch = deny;
globalThis.WebSocket = class { constructor() { deny(); } };
syncBuiltinESMExports();
process.on('exit', () => { process.stderr.write(`networkAttempts=${attempts}\n`); if (attempts) process.exitCode = 1; });
