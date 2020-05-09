import frida

dev = frida.get_usb_device()
dev.open_channel('lockdown:com.apple.webinspector')