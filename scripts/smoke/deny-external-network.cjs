/* eslint-disable @typescript-eslint/no-require-imports, no-undef -- Loaded through NODE_OPTIONS before ESM startup. */
'use strict';

const net = require('node:net');

const originalConnect = net.Socket.prototype.connect;
const loopbackHosts = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

const connectionHost = (args) => {
  const first = args[0];
  if (typeof first === 'object' && first !== null) {
    if (first.path !== undefined) return undefined;
    return first.host ?? first.hostname ?? 'localhost';
  }
  return typeof args[1] === 'string' ? args[1] : 'localhost';
};

net.Socket.prototype.connect = function guardedConnect(...args) {
  const host = connectionHost(args);
  if (host !== undefined && !loopbackHosts.has(String(host).toLowerCase())) {
    const error = Object.assign(new Error('SMOKE_EXTERNAL_NETWORK_BLOCKED'), {
      code: 'SMOKE_EXTERNAL_NETWORK_BLOCKED',
    });
    process.stderr.write('SMOKE_EXTERNAL_NETWORK_BLOCKED\n');
    process.nextTick(() => this.emit('error', error));
    return this;
  }
  return Reflect.apply(originalConnect, this, args);
};

if (process.env.SMOKE_NETWORK_GUARD_CANARY === '1') {
  let blocked = false;
  const socket = new net.Socket();
  socket.once('error', (error) => {
    blocked = error?.code === 'SMOKE_EXTERNAL_NETWORK_BLOCKED';
  });
  socket.connect({ host: 'example.invalid', port: 443 });
  setImmediate(() => {
    process.exitCode = blocked ? 0 : 1;
  });
}
