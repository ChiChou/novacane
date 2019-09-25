import frida

with open('agent.js', 'r') as fp:
  source = fp.read()

dev = frida.get_usb_device()
session = dev.attach('SpringBoard')
script = session.create_script(source)
script.load()
info = script.exports.dumpstate()
print(info)
script.unload()
session.detach()