const Security = Process.getModuleByName('Security');

Interceptor.attach(Security.findExportByName('SSLRead'), {
  onEnter(args) {
    this.data = args[1];
    this.len = args[2];
    this.processed = args[3];
  },
  onLeave(retval) {
    const len = this.processed.readULong();
    const data = this.data.readByteArray(len);
    console.log(`SSLRead(${this.len.toUInt32()})\n${hexdump(data)}`);
  }
});

Interceptor.attach(Security.findExportByName('SSLWrite'), {
  onEnter(args) {
    const data = args[1];
    const len = args[2].toUInt32();

    console.log(`SSLWrite(${len})\n${hexdump(data.readByteArray(len))}`);
  }
});