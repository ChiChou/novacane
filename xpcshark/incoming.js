function findHandler() {
  return new Promise((resolve, reject) => {
    let found = false;
    Module.enumerateSymbols('libxpc.dylib', {
      onMatch(symbol) {
        if (symbol.name == '_xpc_connection_call_event_handler') {
          resolve(symbol.address);
          found = true;
          return 'stop';
        }
      },
      onError: reject,
      onComplete() {
        if (!found) reject(new Error('not found'));
      }
    })
  })
}

async function main() {
  const handler = await findHandler();
  Interceptor.attach(handler, {
    onEnter(args) {
      console.log('call event handler:');
      console.log(new ObjC.Object(args[0]));
      console.log(new ObjC.Object(args[1]));
    }
  })
}

main()
