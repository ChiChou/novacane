const fs = require('fs')
const { promisify } = require('util')
const frida = require('frida')


async function main() {
  const read = promisify(fs.readFile)
  const source = await read('dlopen.js')
  const opt = { runtime: 'v8' }

  const dev = await frida.getLocalDevice();
  // const pid = await dev.spawn(['/usr/bin/stringdups', 'IINA'])
  const pid = await dev.spawn(['/usr/bin/symbols', 'IINA', '-printDemangle'])
  const session = await dev.attach(pid)

  session.detached.connect(() => console.warn('parent detached'));
  const script = await session.createScript(source, opt)

  script.message.connect(async (msg) => {
    // console.debug('message', msg)

    const { payload } = msg;
    if (payload.event === 'spawn') {
      const session2 = await dev.attach(payload.pid);
      const script2 = await session2.createScript(source, opt);
      session2.detached.connect(() => console.warn('child detached'));
      await dev.resume(payload.pid);
      await script2.load();
    }
  })
  await script.load()
  await dev.resume(pid)
}

main().catch(e => {
  console.error(e)
})