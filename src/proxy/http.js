import { 有效数据长度, 数据转Uint8Array, 拼接字节数据, stripIPv6Brackets, isIPHostname } from './forward.js';

export { 有效数据长度, 数据转Uint8Array, 拼接字节数据, stripIPv6Brackets, isIPHostname };

/**
 * HTTP proxy CONNECT handshake (plain or HTTPS-wrapped).
 * Uses the global `parsedSocks5Address` for proxy credentials and address.
 * @param {string} targetHost
 * @param {number} targetPort
 * @param {Uint8Array|null} initialData
 * @param {boolean} HTTPS代理 - whether to wrap in TLS to the proxy
 * @param {Function} TCP连接
 * @returns {Promise<import('streams').WritableStream|any>}
 */
async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, TCP连接) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const socket = HTTPS代理
        ? TCP连接({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
        : TCP连接({ hostname, port });
    const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    try {
        if (HTTPS代理) await socket.opened;

        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await writer.write(encoder.encode(request));
        writer.releaseLock();

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const { done, value } = await reader.read();
            if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
            responseBuffer = new Uint8Array([...responseBuffer, ...value]);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
        const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
        if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        reader.releaseLock();

        if (有效数据长度(initialData) > 0) {
            const 远端写入器 = socket.writable.getWriter();
            await 远端写入器.write(initialData);
            远端写入器.releaseLock();
        }

        // CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
        if (bytesRead > headerEndIndex) {
            const { readable, writable } = new TransformStream();
            const transformWriter = writable.getWriter();
            await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
            transformWriter.releaseLock();
            socket.readable.pipeTo(writable).catch(() => { });
            return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
        }

        return socket;
    } catch (error) {
        try { writer.releaseLock() } catch (e) { }
        try { reader.releaseLock() } catch (e) { }
        try { socket.close() } catch (e) { }
        throw error;
    }
}

/**
 * HTTPS proxy CONNECT via TLS to the proxy, then CONNECT to target.
 * Uses the global `parsedSocks5Address` and `TlsClient`.
 * @param {string} targetHost
 * @param {number} targetPort
 * @param {Uint8Array|null} initialData
 * @param {Function} TCP连接
 * @returns {Promise<{readable: ReadableStream, writable: WritableStream, closed: Promise, close: Function}>}
 */
async function httpsConnect(targetHost, targetPort, initialData, TCP连接) {
    const { username, password, hostname, port } = parsedSocks5Address;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let tlsSocket = null;
    const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
    const 打开HTTPS代理TLS = async (allowChacha = false) => {
        const proxySocket = TCP连接({ hostname, port });
        try {
            await proxySocket.opened;
            const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
            await socket.handshake();
            log(`[HTTPS代理] TLS版本: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
            return socket;
        } catch (error) {
            try { proxySocket.close() } catch (e) { }
            throw error;
        }
    };
    try {
        try {
            tlsSocket = await 打开HTTPS代理TLS(false);
        } catch (error) {
            if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
            log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${error?.message || error}`);
            tlsSocket = await 打开HTTPS代理TLS(true);
        }

        const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
        const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
        await tlsSocket.write(encoder.encode(request));

        let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
        while (headerEndIndex === -1 && bytesRead < 8192) {
            const value = await tlsSocket.read();
            if (!value) throw new Error('HTTPS 代理在返回 CONNECT 响应前关闭连接');
            responseBuffer = 拼接字节数据(responseBuffer, value);
            bytesRead = responseBuffer.length;
            const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
            if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
        }

        if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
        const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
        const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
        if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

        if (有效数据长度(initialData) > 0) await tlsSocket.write(数据转Uint8Array(initialData));
        const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
        let closedSettled = false, resolveClosed, rejectClosed;
        const settleClosed = (settle, value) => {
            if (!closedSettled) {
                closedSettled = true;
                settle(value);
            }
        };
        const closed = new Promise((resolve, reject) => {
            resolveClosed = resolve;
            rejectClosed = reject;
        });
        const close = () => {
            try { tlsSocket.close() } catch (e) { }
            settleClosed(resolveClosed);
        };
        const readable = new ReadableStream({
            async start(controller) {
                try {
                    if (有效数据长度(bufferedData) > 0) controller.enqueue(bufferedData);
                    while (true) {
                        const data = await tlsSocket.read();
                        if (!data) break;
                        if (data.byteLength > 0) controller.enqueue(data);
                    }
                    try { controller.close() } catch (e) { }
                    settleClosed(resolveClosed);
                } catch (error) {
                    try { controller.error(error) } catch (e) { }
                    settleClosed(rejectClosed, error);
                }
            },
            cancel() {
                close();
            }
        });
        const writable = new WritableStream({
            async write(chunk) {
                await tlsSocket.write(数据转Uint8Array(chunk));
            },
            close,
            abort(error) {
                close();
                if (error) settleClosed(rejectClosed, error);
            }
        });
        return { readable, writable, closed, close };
    } catch (error) {
        try { tlsSocket?.close() } catch (e) { }
        throw error;
    }
}

export { httpConnect, httpsConnect };
