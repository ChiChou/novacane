if (Process.arch !== "arm64") throw new Error("Unsupported architecture");

const boringssl = Module.load("/usr/lib/libboringssl.dylib");
const { address } = boringssl.enumerateSymbols().find((s) => s.name.includes("ssl_log_secret"));

if (!address) throw new Error("ssl_log_secret not found");

/**
 *
 * @param {NativePointer} address
 * @returns {Number}
 */
function findOffset(address) {
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

const offset = findOffset(address);
Interceptor.attach(boringssl.findExportByName("SSL_CTX_set_info_callback"), {
  onEnter: function (args) {
    const ssl = args[0];
    const cb = ssl.add(offset);
    cb.writePointer(logCallback.sign('ia'));
  },
});
