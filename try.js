const xpcConnectionCreateMachService = new NativeFunction(Module.findExportByName(null, 'xpc_connection_create_mach_service'), 'pointer', ['pointer', 'pointer', 'int']);
const xpcConnectionSetEventHandler = new NativeFunction(Module.findExportByName(null, 'xpc_connection_set_event_handler'), 'void', ['pointer', 'pointer']);
const xpcConnectionResume = new NativeFunction(Module.findExportByName(null, 'xpc_connection_resume'), 'void', ['pointer']);

const conn = xpcConnectionCreateMachService(Memory.allocUtf8String('com.apple.hiservices-xpcservice'), NULL, 0);
xpcConnectionSetEventHandler(conn, new ObjC.Block({
  argTypes: ['object'],
  retType: 'void',
  implementation: function(msg) {
    console.log('event', msg)
  }
}));

xpcConnectionResume(conn)
