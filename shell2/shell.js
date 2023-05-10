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

async function main() {
  const device = await frida.getUsbDevice();
  const port = await scan(device);
  const channel = await device.openChannel(`tcp:${port}`);

  const username = 'root'
  const password = 'alpine'

  const pipeStream = stream => {
    const { stdin, stdout, stderr } = process;
    const { isTTY } = stdout;

    if (isTTY && stdin.setRawMode) stdin.setRawMode(true);

    stream.pipe(stdout);
    stream.stderr.pipe(stderr);
    stdin.pipe(stream);

    const onResize = isTTY && (() => stream.setWindow(stdout.rows, stdout.columns, null, null));
    if (isTTY) {
      stream.once('data', onResize)
      process.stdout.on('resize', onResize)
    }
    stream.on('close', () => {
      if (isTTY) process.stdout.removeListener('resize', onResize)
      stream.unpipe()
      stream.stderr.unpipe()
      stdin.unpipe()
      if (stdin.setRawMode) stdin.setRawMode(false)
      stdin.unref()
    })
  }

  const conn = new Client();
  conn.on('ready', () => {
    conn.shell({ term: process.env.TERM || 'vt100' }, (err, stream) => {
      if (err) {
        reject(err)
        return
      }
      pipeStream(stream)
      stream.on('close', () => {
        conn.end();
      })
    });
  }).connect({
    sock: channel,
    username,
    password
  });
}

main()