const frida = require('frida');
const net = require('net');

async function main() {
  const device = await frida.getUsbDevice();
  net.createServer(async (socket) => {
    const channel = await device.openChannel('tcp:22');
    socket.pipe(channel).pipe(socket);
    socket.on('close', () => channel.destroy())
      .on('error', console.error.bind(console));
  }).listen(62222);
}

main();
