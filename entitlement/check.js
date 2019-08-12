const SecTaskCopyValueForEntitlement = Module.findExportByName(null, 'SecTaskCopyValueForEntitlement');
const CFRelease = new NativeFunction(Module.findExportByName(null, 'CFRelease'), 'void', ['pointer']);
const CFStringGetCStringPtr = new NativeFunction(Module.findExportByName(null, 'CFStringGetCStringPtr'),
  'pointer', ['pointer', 'uint32']);
const kCFStringEncodingUTF8 = 0x08000100;
Interceptor.attach(SecTaskCopyValueForEntitlement, {
  onEnter: function (args) {
    const p = CFStringGetCStringPtr(args[1], kCFStringEncodingUTF8);
    const ent = Memory.readUtf8String(p);
    console.log('check for entitlement:', ent)
  }
})