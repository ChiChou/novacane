const SecTaskCopyValueForEntitlement = Module.findExportByName(null, 'SecTaskCopyValueForEntitlement');
const CFRelease = new NativeFunction(Module.findExportByName(null, 'CFRelease'), 'void', ['pointer']);
const CFStringGetCStringPtr = new NativeFunction(Module.findExportByName(null, 'CFStringGetCStringPtr'),
  'pointer', ['pointer', 'uint32']);
const kCFStringEncodingUTF8 = 0x08000100;
Interceptor.attach(SecTaskCopyValueForEntitlement, {
  onEnter: function (args) {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n')
    const p = CFStringGetCStringPtr(args[1], kCFStringEncodingUTF8);
    const ent = Memory.readUtf8String(p);
    const description = SecTaskCopyDebugDescription(args[0])
    if (!description.isNull()) {
      const pDesc = CFStringGetCStringPtr(description, kCFStringEncodingUTF8)
      console.log('enable inspector for', Memory.readUtf8String(pDesc))
      CFRelease(description)
    }
    console.log('check for entitlement:', ent, 'target:', pDesc)
  }
})