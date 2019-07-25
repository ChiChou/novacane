const frida = require('frida')

module.exports = async function () {
  const dev = await frida.getUsbDevice()
  const pid = await dev.spawn('/bin/bash', {
    stdio: 'pipe',
    cwd: '/var/root',
  })

  process.stdin.on('data', data => dev.input(pid, data))
  const mapping = [null, process.stdout, process.stderr]
  dev.output.connect((processId, fd, data) => {
    if (processId === pid)
      mapping[fd].write(data)
  })

  const session = await dev.attach(pid)
  session.detached.connect(() => process.exit())
  await dev.resume(pid)

  async function cleanup() {
    await session.detach()
    await dev.kill(pid)
  }

  process.on('SIGINT', cleanup)
  process.on('SIGTERM', cleanup)
  process.on('exit', cleanup)
}

