Module.enumerateSymbols('libxpc.dylib', {
  onMatch(symbol) {
    if (symbol.name == '_xpc_connection_call_event_handler') {
      Interceptor.attach(symbol.address, {
        onEnter(args) {
          console.log('call event handler:')
          console.log(new ObjC.Object(args[0]));
          console.log(new ObjC.Object(args[1]));
        }
      })

      return 'stop';
    }
  },
  onComplete() {}
})