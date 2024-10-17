if (Process.arch !== "arm64") throw new Error("Unsupported architecture");

const boringssl = Process.getModuleByName("libboringssl.dylib");

/**
 *
 * @returns {Number}
 */
function findOffset() {
  const moduleMap = new ModuleMap(m => m.name === "libboringssl.dylib");
  const addresses =
    DebugSymbol.findFunctionsMatching('bssl::ssl_log_secret*')
      .filter(addr => moduleMap.has(addr))

  if (!addresses.length) throw new Error("bssl::ssl_log_secret not found");

  const address = addresses.at(0);
  for (let i = 0; i < 16; i++) {
    const addr = address.add(i * 4);
    const instr = Instruction.parse(addr);

    if (instr.mnemonic === "ldr" && instr.operands.length === 2) {
      const op0 = instr.operands[0];
      const op1 = instr.operands[1];
      if (
        op0.type === "reg" &&
        op0.value === "x8" &&
        op1.type === "mem" &&
        op1.value.base === "x8"
      ) {
        return op1.value.disp;
      }
    }
  }

  throw new Error("Offset not found");
}

function keyLogger(ssl, line) {
  console.log(line.readCString());
}

const logCallback = new NativeCallback(keyLogger, "void", ["pointer", "pointer"]);
const offset = findOffset();

Interceptor.attach(boringssl.findExportByName("SSL_CTX_set_info_callback"), {
  onEnter: function (args) {
    const ssl = args[0];
    const cb = ssl.add(offset);
    cb.writePointer(logCallback.sign('ia'));
  },
});
