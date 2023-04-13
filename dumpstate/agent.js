function dumpstate() {
  Module.load('/System/Library/PrivateFrameworks/ServiceManagement.framework/ServiceManagement');
  const copyAll = new NativeFunction(Module.findExportByName('ServiceManagement', 'SMCopyAllJobDictionaries'), 'pointer', ['pointer']);
  const release = new NativeFunction(Module.findExportByName(null, 'CFRelease'), 'void', ['pointer']);
  const kSMDomainSystemLaunchd = Module.findExportByName(null, 'kSMDomainSystemLaunchd');
  const result = copyAll(kSMDomainSystemLaunchd);
  const description = new ObjC.Object(result).toString();
  release(result);
  return description;
}

console.log(dumpstate());