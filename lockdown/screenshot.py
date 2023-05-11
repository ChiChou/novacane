import frida
import struct
import plistlib


class Channel(object):
    def __init__(self, name=''):
        self.name = name
        self.dev = frida.get_usb_device()
        self.pipe = self.dev.open_channel('lockdown:%s' % name)

        if len(name):
            self.version_exchange()
            self.dl = True
        else:
            self.dl = False

    def version_exchange(self):
        magic, major, minor = self.read()
        assert major >= 300
        assert magic == 'DLMessageVersionExchange'
        assert minor > -1
        self.write(['DLMessageVersionExchange', 'DLVersionsOk', major])

        magic, = self.read()
        assert magic == 'DLMessageDeviceReady'

    def send(self, msg):
        return self.write(['DLMessageProcessMessage', msg] if self.dl else msg)

    def recv(self):
        if self.dl:
            magic, msg = self.read()
            assert magic == 'DLMessageProcessMessage'
            return msg
        else:
            return self.read()

    def write(self, msg):
        buf = plistlib.dumps(msg, fmt=plistlib.FMT_BINARY)
        self.pipe.write_all(struct.pack('>I', len(buf)))
        self.pipe.write_all(buf)

    def read(self):
        size, = struct.unpack('>L', self.pipe.read(4))
        response = self.pipe.read_all(size)
        return plistlib.loads(response)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        self.pipe.close()


# with Channel() as channel:
#     channel.send({
#         'Request': 'GetValue'
#     })
#     print(channel.recv().get('Value'))

# with Channel() as channel:
#     channel.send({
#         'Label': 'iTunesHelper',
#         'Request': 'QueryType'
#     })
#     print(channel.recv())

with Channel('com.apple.mobile.screenshotr') as channel:
    channel.send({
      'MessageType': 'ScreenShotRequest'
    })

    response = channel.recv()
    assert response['MessageType'] == 'ScreenShotReply'
    with open('screenshot.png', 'wb') as fp:
        fp.write(response['ScreenShotData'])

