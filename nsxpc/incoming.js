if (Process.arch !== 'arm64') throw new Error('ARM 64-bit only, please contribute for other archs');

function findCaller() {
    const methods = ['- _decodeAndInvokeMessageWithEvent:flags:', '- _decodeAndInvokeMessageWithEvent:reply:flags:'];
    for (const sel of methods) {
        const method = ObjC.classes.NSXPCConnection[sel]
        if (method) return method.implementation.strip();
    }
    throw new Error('not found');
}


/**
 * faster than DebugSymbol.getFunctionByName('__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S2__)
 * @param {NativePointer} start 
 */
function *findPatchPoints(start) {
    const range = Process.findRangeByAddress(start)
    const end = range.base.add(range.size)
    let p = start
    let counter = 0

    /**
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S0__
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT__
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S4__
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S2__
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S3__
__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S1__
     */
    while (p.compare(end) < 0) {
        const inst = Instruction.parse(p)
        if (inst.mnemonic === 'bl') {
            const callee = inst.operands[0].value
            const symbol = DebugSymbol.fromAddress(ptr(callee))

            if (symbol) {
                const m = symbol.name.match(/^__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT(_S([0-4]))?__$/)
                if (m) {
                    const count = m[1] ? parseInt(m[2]) : 0;
                    yield [p, count]
                    if (++counter > 5) return
                }
            }
        }

        p = inst.next
    }

    throw new Error('Unable to resolve all patch points');
}

for (const [addr, count] of findPatchPoints(findCaller())) {
    console.log(`hooking ${addr} with args count ${count}`);

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