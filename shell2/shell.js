const net = require('net');
const frida = require('frida');
const { Client } = require('ssh2');


/**
 * 
 * @param {frida.Device} device 
 * @returns {Number}
 */
async function scan(device) {
    const canidates = [22, 44]
    for (const port of canidates) {
        let channel

        try {
            channel = await device.openChannel(`tcp:${port}`);
        } catch(e) {
            continue
        }

        const yes = await new Promise((resolve) => {
            channel.once('data', data => resolve(data.readUInt32BE() === 0x5353482d)); // SSH-
            setTimeout(() => resolve(false), 500);
        })

        if (yes) return port
    }

    throw Error('port not found')
}

/**
 * 
 * @param {frida.Device} device
 * @returns {Promise<net.Server>}
 */
async function iproxy(device) {
    const port = await scan(device);
    return new Promise((resolve) => {
        const server = net.createServer(async (socket) => {
            const channel = await device.openChannel(`tcp:${port}`);
            socket.pipe(channel);
            channel.pipe(socket);
            socket.on('close', () => {
                channel.unpipe();
                socket.unpipe();
                socket.unref();
                channel.destroy();
            }).on('error', console.error.bind(console));
        }).listen(0, () => {
            resolve(server);
        });
    });
}


async function main() {
    const device = await frida.getUsbDevice();
    const proxy = await iproxy(device);

    const port = proxy.address().port
    const host = '127.1'
    const username = 'root'
    const password = 'alpine'

    const pipeStream = stream => {
        const { stdin, stdout, stderr } = process;
        const { isTTY } = stdout;

        if (isTTY && stdin.setRawMode) stdin.setRawMode(true);

        stream.pipe(stdout);
        stream.stderr.pipe(stderr);
        stdin.pipe(stream);

        const onResize = isTTY && (() => stream.setWindow(stdout.rows, stdout.columns, null, null));
        if (isTTY) {
            stream.once('data', onResize)
            process.stdout.on('resize', onResize)
        }
        stream.on('close', () => {
            if (isTTY) process.stdout.removeListener('resize', onResize)
            stream.unpipe()
            stream.stderr.unpipe()
            stdin.unpipe()
            if (stdin.setRawMode) stdin.setRawMode(false)
            stdin.unref()
        })
    }

    const conn = new Client();
    await new Promise((resolve) => {
        conn.on('ready', function () {
            conn.shell({ term: process.env.TERM || 'vt100' }, (err, stream) => {
                if (err) {
                    reject(err)
                    return
                }
                pipeStream(stream)
                stream.on('close', () => resolve(true))
            });
        }).connect({
            host,
            port,
            username,
            password
        });
    });

    process.exit();
}

main()