const nw = Process.findModuleByName("Network");

const nw_connection_copy_endpoint = new NativeFunction(nw.getExportByName('nw_connection_copy_endpoint'), 'pointer', ['pointer']);
const nw_connection_copy_parameters = new NativeFunction(nw.getExportByName('nw_connection_copy_parameters'), 'pointer', ['pointer']);
const nw_connection_copy_current_path = new NativeFunction(nw.getExportByName('nw_connection_copy_current_path'), 'pointer', ['pointer']);
const nw_path_copy_effective_local_endpoint = new NativeFunction(nw.getExportByName('nw_path_copy_effective_local_endpoint'), 'pointer', ['pointer']);
const nw_path_copy_effective_remote_endpoint = new NativeFunction(nw.getExportByName('nw_path_copy_effective_remote_endpoint'), 'pointer', ['pointer']);

/**
 * @param {NativePointer} conn 
 */
function endpoints(conn) {
  const path = nw_connection_copy_current_path(conn);
  const local = nw_path_copy_effective_local_endpoint(path);
  const remote = nw_path_copy_effective_remote_endpoint(path);
  return [local, remote].map(p => new ObjC.Object(p).toString()).join(' -> ');
}

Interceptor.attach(nw.getExportByName('nw_connection_send'), {
  onEnter(args) {
    const conn = args[0];
    const pair = endpoints(conn);

    if (args[1].isNull()) {
      console.log(pair + '\n(empty)\n');
      return;
    }

    const data = new ObjC.Object(args[1]);
    const xxd = hexdump(data.bytes(), { length: data.length() });
    console.log(`${pair}\n${xxd}\n`);
  }
})

Interceptor.attach(Module.findExportByName(null, "nw_connection_receive"), {
  onEnter(args) {
    const conn = new ObjC.Object(args[0]);
    const block = new ObjC.Block(args[3]);

    const original = block.implementation;
    block.implementation = function (data, ctx, isComplete, err) {
      const pair = endpoints(conn);
      const xxd = data ? hexdump(data.bytes(), { length: data.length() }) : '(empty)';
      console.log(`${pair}\n${xxd}\n`);
      original.apply(this, arguments);
    }
  }
});
