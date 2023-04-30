/**
 * @param {NativePointer} start 
 */
function *findPatchPoints() {
    for (const symbol of Module.enumerateSymbols('Foundation')) {
        const m = symbol.name.match(/^__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT(_S([0-4]))?__$/)
        if (m) {
            const count = m[1] ? parseInt(m[2]) : 0;
            yield [symbol.address, count]
        }
    }
}

for (const [addr, count] of findPatchPoints()) {
    console.log(`hook ${addr} with args count ${count}`);

    const callbacks = count === 0 ? {
        onEnter(args) {
            const invocation = new ObjC.Object(args[0]);
            const selector = invocation.selector();
            const selectorName = ObjC.selectorAsString(selector);
            const signature = invocation.methodSignature();
            const argCount = signature.numberOfArguments();

            const formattedArgs = [];
            const v = Memory.alloc(Process.pointerSize);
            for (let i = 2; i < argCount; i++) {
                invocation.getArgument_atIndex_(v, i);
                const t = signature.getArgumentTypeAtIndex_(i);
                const arg = v.readPointer();
                const wrapped = t === '@' ? new ObjC.Object(arg) : arg;
                formattedArgs.push(wrapped);
            }

            const targetClass = invocation.target();
            const detail = selectorName.replace(/:/g, () => `:${formattedArgs.shift()} `);
            console.log(`${targetClass} ${selectorName} ${detail}`);
        }
    } : {
        onEnter(args) {
            const targetClass = new ObjC.Object(args[0]);
            const selectorName = ObjC.selectorAsString(args[1]);

            const formattedArgs = [];
            for (let i = 0; i < count; i++) {
                const str = new ObjC.Object(args[2 + i]);
                formattedArgs.push(str);
            }

            const detail = selectorName.replace(/:/g, () => `:${formattedArgs.shift()} `);
            console.log(`${targetClass} ${detail})}`);
        }
    }

    Interceptor.attach(addr, callbacks)
}