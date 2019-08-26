const POSIX_SPAWN_START_SUSPENDED = 0x0080


Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
  onEnter(args) {
    if (!args[0].toInt32()) return;

    const path = Memory.readUtf8String(args[0])
    console.log('dlopen', path);
  }
})

const getFlags = new NativeFunction(Module.findExportByName(null, 'posix_spawnattr_getflags'), 'void', ['pointer', 'pointer']);
const setFlags = new NativeFunction(Module.findExportByName(null, 'posix_spawnattr_setflags'), 'void', ['pointer', 'int']);

Interceptor.attach(Module.findExportByName(null, 'posix_spawn'), {
  onEnter(args) {
    this.ppid = args[0]
    const attr = args[3];
    const pFlags = Memory.alloc(4);
    getFlags(attr, pFlags);
    let flags = Memory.readShort(pFlags);
    // console.log('flags', flags);
    flags |= POSIX_SPAWN_START_SUSPENDED;
    // console.log('flags after', flags);
    setFlags(attr, flags);
  },
  onLeave() {
    const pid = Memory.readInt(this.ppid)
    console.log('posix_spawn pid:', pid)
    send({ event: 'spawn', pid })
  }
})

Interceptor.attach(Module.findExportByName(null, 'exit'), {
  onEnter() {
    console.log('exit')
  }
})