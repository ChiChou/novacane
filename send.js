
function hook(symbol) {
  Interceptor.attach(Module.findExportByName(null, symbol), {
    onEnter: function (args) {
      const conn = new ObjC.Object(args[0]);
      const msg = new ObjC.Object(args[1]);
      const content = [symbol + ':', conn, msg];
      if (symbol === 'xpc_connection_send_message_with_reply' && !args[3].isNull()) {
        // async reply
        const cb = new ObjC.Block(args[3]).implementation;
        const block =  new ObjC.Block({
          retType: 'void',
          argTypes: ['object'],
          implementation: function(reply) {
            console.log('async reply:\n' + new ObjC.Object(reply));
            return cb(reply);
          }
        });
      }
      console.log(content.join('\n'));
    },
    onLeave(retVal) {
      if (symbol === 'xpc_connection_send_message_with_reply_sync') {
        console.log('send sync, reply:\n' + new ObjC.Object(retVal));
      }
    }
  })
}

hook('xpc_connection_send_message');
hook('xpc_connection_send_message_with_reply');
hook('xpc_connection_send_message_with_reply_sync');
