#!/usr/bin/env node

'use strict';

const frida = require('frida');
const { Client } = require('ssh2');


/**
 * 
 * @param {frida.Device} device 
 * @returns {Promise<Number>}
 */
async function scan(device) {
  const canidates = [22, 44]
  for (const port of canidates) {
    const ok = await device.openChannel(`tcp:${port}`)
      .then((channel) => new Promise((resolve) => {
        channel
          .once('data', data => {
            resolve(data.readUInt32BE() === 0x5353482d); // SSH-
            channel.destroy();
          })
          .once('error', () => {
            resolve(false);
          });
      }))
      .catch(() => false);

    if (ok) return port;
  }
  throw Error('port not found')
}

async function connect(device, user='root', password='alpine') {
  const port = await scan(device);
  const channel = await device.openChannel(`tcp:${port}`);

  const client = new Client();
  return new Promise((resolve, reject) => {
    client
      .on('ready', () => resolve(client))
      .on('error', reject)
      .connect({
        sock: channel,
        username: user,
        password,
      });
  });
}

async function interactive(client) {
  const { stdin, stdout, stderr } = process;
  const { isTTY } = stdout;

  return new Promise((resolve, reject) => {
    client.shell({ term: process.env.TERM || 'vt100' }, (err, stream) => {
      if (err) {
        return reject(err);
      }

      if (isTTY && stdin.setRawMode) {
        stdin.setRawMode(true);
      }

      stream.pipe(stdout);
      stream.stderr.pipe(stderr);
      stdin.pipe(stream);

      const onResize = () => {
        const [w, h] = process.stdout.getWindowSize();
        stream.setWindow(`${stdout.rows}`, `${stdout.columns}`, `${w}`, `${h}`)
      };

      const cleanup = () => {
        if (isTTY) {
          stdout.removeListener('resize', onResize);
          if (stdin.setRawMode) stdin.setRawMode(false);
        }

        stream.unpipe();
        stream.stderr.unpipe();
        stdin.unpipe();

        // stdin.unref();
        // stdout.unref();
        // stderr.unref();
      }

      const onError = (err) => {
        cleanup();
        reject(err);
      }

      if (isTTY) {
        stream.once('data', onResize);
        process.stdout.on('resize', onResize);
      }

      client.once('end', () => {
        cleanup();
        resolve();
      });

      stream.on('error', onError);
    });
  });
}

async function main() {
  const device = await frida.getUsbDevice();
  const client = await connect(device);

  await interactive(client);
}

main();