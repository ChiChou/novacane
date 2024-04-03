// DebugSymbol.findFunctionsMatching is faster than DebugSymbol.getFunctionByName

const invoker = DebugSymbol.findFunctionsMatching('__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT__').pop()
Interceptor.attach(invoker, {
    onEnter(args) {
        const invocation = new ObjC.Object(args[0]);
        const target = invocation.target();
        const selector = invocation.selector();

        const imp = target.methodForSelector_(selector).strip();
        const signature = target.methodSignatureForSelector_(selector);

        this.hook = Interceptor.attach(imp, {
            onEnter(innerArgs) {
                const nargs = signature.numberOfArguments();
                const formattedArgs = [];
                for (let i = 2; i < nargs; i++) { // skip self and selector
                    const arg = innerArgs[i];
                    /** @type {ObjC.Object} */
                    const t = signature.getArgumentTypeAtIndex_(i);
                    const wrapped = t.toString().startsWith('@') ? new ObjC.Object(arg) : arg;
                    formattedArgs.push(wrapped);
                }

                const detail = ObjC.selectorAsString(selector).replace(/:/g, () => `:${formattedArgs.shift()} `);
                console.log(`-> ${target} ${detail})}`);
            }
        })
    },
    onLeave() {
        this.hook.detach();
    }
})

for (const func of DebugSymbol.findFunctionsMatching('__NSXPCCONNECTION_IS_CALLING_OUT_TO_EXPORTED_OBJECT_S*')) {
    const plain = func.strip();
    if (Process.findModuleByAddress(plain)?.name !== 'Foundation') continue;

    // console.log(DebugSymbol.fromAddress(func));

    Interceptor.attach(plain, {
        onEnter(args) {
            const targetClass = new ObjC.Object(args[0]);
            const selectorName = ObjC.selectorAsString(args[1]);
            const signature = targetClass.methodSignatureForSelector_(args[1]);
            const nargs = signature.numberOfArguments();
            const formattedArgs = [];
            for (let i = 2; i < nargs; i++) { // skip self and selector
                const arg = args[i];
                /** @type {ObjC.Object} */
                const t = signature.getArgumentTypeAtIndex_(i);
                const wrapped = t.toString().startsWith('@') ? new ObjC.Object(arg) : arg;
                formattedArgs.push(wrapped);
            }

            const detail = selectorName.replace(/:/g, () => `:${formattedArgs.shift()} `);
            console.log(`-> ${targetClass} ${detail})}`);
        }
    })
}