import { socks5Connect } from './socks5.js';
import { httpConnect, httpsConnect } from './http.js';
import { turnConnect } from './turn.js';
import { sstpConnect } from './sstp.js';

export { socks5Connect, httpConnect, httpsConnect, turnConnect, sstpConnect };

const SSAEAD标签长度 = 16, SSNonce长度 = 12;
const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
const SS文本编码器 = new TextEncoder(), SS文本解码器 = new TextDecoder(), SS主密钥缓存 = new Map();

export { SSAEAD标签长度, SSNonce长度, SS子密钥信息, SS文本编码器, SS文本解码器, SS主密钥缓存 };

function 数据转Uint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || 0);
}

function 拼接字节数据(...chunkList) {
    if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
    const chunks = chunkList.map(数据转Uint8Array);
    const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
    return result;
}

function 有效数据长度(data) {
    if (!data) return 0;
    if (typeof data.byteLength === 'number') return data.byteLength;
    if (typeof data.length === 'number') return data.length;
    return 0;
}

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (error) { }
}

async function WebSocket发送并等待(webSocket, payload) {
    const sendResult = webSocket.send(payload);
    if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function stripIPv6Brackets(hostname = '') {
    const host = String(hostname || '').trim();
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPv4(value) {
    const parts = String(value || '').split('.');
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isIPHostname(hostname = '') {
    const host = stripIPv6Brackets(hostname);
    const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
    if (ipv4Regex.test(host)) return true;
    if (!host.includes(':')) return false;
    try {
        new URL(`http://[${host}]/`);
        return true;
    } catch (e) {
        return false;
    }
}

export { 数据转Uint8Array, 拼接字节数据, 有效数据长度, closeSocketQuietly, WebSocket发送并等待, stripIPv6Brackets, isIPv4, isIPHostname };

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

export { formatIdentifier };

function SS递增Nonce计数器(counter) {
    for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SS派生主密钥(passwordText, keyLen) {
    const cacheKey = `${keyLen}:${passwordText}`;
    if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
    const deriveTask = (async () => {
        const pwBytes = SS文本编码器.encode(passwordText || '');
        let prev = new Uint8Array(0), result = new Uint8Array(0);
        while (result.byteLength < keyLen) {
            const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
            input.set(prev, 0); input.set(pwBytes, prev.byteLength);
            prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
            result = 拼接字节数据(result, prev);
        }
        return result.slice(0, keyLen);
    })();
    SS主密钥缓存.set(cacheKey, deriveTask);
    try { return await deriveTask }
    catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

async function SS派生会话密钥(config, masterKey, salt, usages) {
    const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
    const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
    const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
    const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
    const subKey = new Uint8Array(config.keyLen);
    let prev = new Uint8Array(0), written = 0, counter = 1;
    while (written < config.keyLen) {
        const input = 拼接字节数据(prev, SS子密钥信息, new Uint8Array([counter]));
        prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
        const copyLen = Math.min(prev.byteLength, config.keyLen - written);
        subKey.set(prev.subarray(0, copyLen), written);
        written += copyLen; counter += 1;
    }
    return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
    const iv = nonceCounter.slice();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
    SS递增Nonce计数器(nonceCounter);
    return new Uint8Array(ct);
}

async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
    const iv = nonceCounter.slice();
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
    SS递增Nonce计数器(nonceCounter);
    return new Uint8Array(pt);
}

export { SS递增Nonce计数器, SS派生主密钥, SS派生会话密钥, SSAEAD加密, SSAEAD解密 };

async function 转发木马UDP数据(chunk, webSocket, 上下文, request) {
    const 当前块 = 数据转Uint8Array(chunk);
    const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
    const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
    let cursor = 0;

    while (cursor < input.byteLength) {
        const packetStart = cursor;
        const atype = input[cursor];
        let addrCursor = cursor + 1;
        let addrLen = 0;
        if (atype === 1) addrLen = 4;
        else if (atype === 4) addrLen = 16;
        else if (atype === 3) {
            if (input.byteLength < addrCursor + 1) break;
            addrLen = 1 + input[addrCursor];
        } else throw new Error(`invalid trojan udp addressType: ${atype}`);

        const portCursor = addrCursor + addrLen;
        if (input.byteLength < portCursor + 6) break;

        const port = (input[portCursor] << 8) | input[portCursor + 1];
        const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
        if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

        const payloadStart = portCursor + 6;
        const payloadEnd = payloadStart + payloadLength;
        if (input.byteLength < payloadEnd) break;

        const 地址端口头 = input.slice(packetStart, portCursor + 2);
        const payload = input.slice(payloadStart, payloadEnd);
        cursor = payloadEnd;

        if (port !== 53) throw new Error('UDP is not supported');
        if (!payload.byteLength) continue;

        let tcpDNS查询 = payload;
        if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
            tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
            tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
            tcpDNS查询[1] = payload.byteLength & 0xff;
            tcpDNS查询.set(payload, 2);
        }

        const dns响应上下文 = { 缓存: new Uint8Array(0) };
        await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
            const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
            const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
            const 响应帧列表 = [];
            let responseCursor = 0;
            while (responseCursor + 2 <= 响应输入.byteLength) {
                const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
                const dnsStart = responseCursor + 2;
                const dnsEnd = dnsStart + dnsLen;
                if (dnsEnd > 响应输入.byteLength) break;
                const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
                const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
                frame.set(地址端口头, 0);
                frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
                frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
                frame[地址端口头.byteLength + 2] = 0x0d;
                frame[地址端口头.byteLength + 3] = 0x0a;
                frame.set(dnsPayload, 地址端口头.byteLength + 4);
                响应帧列表.push(frame);
                responseCursor = dnsEnd;
            }
            dns响应上下文.缓存 = 响应输入.slice(responseCursor);
            return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
        });
    }

    if (上下文) 上下文.缓存 = input.slice(cursor);
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null) {
    log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${反代IP} | 反代兜底: ${启用反代兜底 ? '是' : '否'} | 反代类型: ${启用SOCKS5反代 || 'proxyip'} | 全局: ${启用SOCKS5全局反代 ? '是' : '否'}`);
    const 连接超时毫秒 = 1000;
    let 已通过代理发送首包 = false;
    const TCP连接 = 创建请求TCP连接器(request);

    async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
        await Promise.race([
            remoteSock.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
        ]);
    }

    async function 打开TCP连接(address, port) {
        const remoteSock = TCP连接({ hostname: address, port });
        try {
            await 等待连接建立(remoteSock);
            return remoteSock;
        } catch (err) {
            try { remoteSock?.close?.() } catch (e) { }
            throw err;
        }
    }

    async function 写入首包(remoteSock, data) {
        if (有效数据长度(data) <= 0) return;
        const writer = remoteSock.writable.getWriter();
        try { await writer.write(数据转Uint8Array(data)) }
        finally { try { writer.releaseLock() } catch (e) { } }
    }

    async function 并发打开候选连接(候选列表) {
        if (候选列表.length === 1) {
            const 候选 = 候选列表[0];
            return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
        }
        const attempts = 候选列表.map(候选 => 打开TCP连接(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })));
        let winner = null;
        try {
            winner = await Promise.any(attempts);
            return winner;
        } finally {
            if (winner) {
                for (const attempt of attempts) {
                    attempt.then(({ socket }) => {
                        if (socket !== winner.socket) {
                            try { socket?.close?.() } catch (e) { }
                        }
                    }).catch(() => { });
                }
            }
        }
    }

    async function 构建预加载竞速候选列表(address, port) {
        if (!预加载竞速拨号 || isIPHostname(address)) return null;
        log(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
        const [aRecords, aaaaRecords] = await Promise.all([
            DoH查询(address, 'A'),
            DoH查询(address, 'AAAA')
        ]);
        const ipv4List = [...new Set(aRecords.flatMap(r => {
            const data = r.data;
            return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
        }))];
        const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
            const data = r.data;
            return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
        }))];
        const 拨号上限 = Math.max(1, TCP并发拨号数 | 0);
        const ipList = ipv4List.length >= 拨号上限
            ? ipv4List.slice(0, 拨号上限)
            : ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
        const 使用记录类型 = ipv4List.length > 0
            ? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
            : 'AAAA';
        if (ipList.length === 0) {
            log(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
            return null;
        }
        const 选中IP列表 = ipList;
        log(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${使用记录类型}记录，竞速拨号 ${选中IP列表.length}/${拨号上限}: ${选中IP列表.join(', ')}`);
        return 选中IP列表.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
    }

    async function connectDirect(address, port, data = null, 启用预加载 = false) {
        const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
        const 候选列表 = 预加载候选列表 || Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
        log(预加载候选列表
            ? `[TCP直连] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
            : `[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
        let socket = null;
        try {
            const 连接结果 = await 并发打开候选连接(候选列表);
            socket = 连接结果.socket;
            if (预加载候选列表) {
                const winner = 连接结果.candidate;
                log(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
            }
            await 写入首包(socket, data);
            return socket;
        } catch (err) {
            try { socket?.close?.() } catch (e) { }
            if (预加载候选列表) log(`[TCP直连] 预加载竞速失败: ${err.message || err}`);
            throw err;
        }
    }

    async function connectProxyIP(address, port, data = null, 所有反代数组 = null, 启用反代失败兜底 = true) {
        if (所有反代数组 && 所有反代数组.length > 0) {
            for (let i = 0; i < 所有反代数组.length; i += TCP并发拨号数) {
                const 候选列表 = [];
                for (let j = 0; j < TCP并发拨号数 && i + j < 所有反代数组.length; j++) {
                    const 反代数组索引 = (缓存反代数组索引 + i + j) % 所有反代数组.length;
                    const [反代地址, 反代端口] = 所有反代数组[反代数组索引];
                    候选列表.push({ hostname: 反代地址, port: 反代端口, index: 反代数组索引 });
                }
                let socket = null, candidate = null;
                try {
                    log(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
                    const 连接结果 = await 并发打开候选连接(候选列表);
                    socket = 连接结果.socket;
                    candidate = 连接结果.candidate;
                    await 写入首包(socket, data);
                    log(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
                    缓存反代数组索引 = candidate.index;
                    return socket;
                } catch (err) {
                    try { socket?.close?.() } catch (e) { }
                    log(`[反代连接] 本批连接失败: ${err.message || err}`);
                }
            }
        }

        if (启用反代失败兜底) return connectDirect(address, port, data, false);
        else {
            closeSocketQuietly(ws);
            throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
        }
    }

    async function connecttoPry(允许发送首包 = true) {
        if (remoteConnWrapper.connectingPromise) {
            await remoteConnWrapper.connectingPromise;
            return;
        }

        const 本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
        const 本次首包数据 = 本次发送首包 ? rawData : null;

        const 当前连接任务 = (async () => {
            let newSocket;
            if (启用SOCKS5反代 === 'socks5') {
                log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
                newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接);
            } else if (启用SOCKS5反代 === 'http') {
                log(`[HTTP代理] 代理到: ${host}:${portNum}`);
                newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接);
            } else if (启用SOCKS5反代 === 'https') {
                log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
                newSocket = isIPHostname(parsedSocks5Address.hostname)
                    ? await httpsConnect(host, portNum, 本次首包数据, TCP连接)
                    : await httpConnect(host, portNum, 本次首包数据, true, TCP连接);
            } else if (启用SOCKS5反代 === 'turn') {
                log(`[TURN代理] 代理到: ${host}:${portNum}`);
                newSocket = await turnConnect(parsedSocks5Address, host, portNum, TCP连接);
                if (有效数据长度(本次首包数据) > 0) {
                    const writer = newSocket.writable.getWriter();
                    try { await writer.write(数据转Uint8Array(本次首包数据)) }
                    finally { try { writer.releaseLock() } catch (e) { } }
                }
            } else if (启用SOCKS5反代 === 'sstp') {
                log(`[SSTP代理] 代理到: ${host}:${portNum}`);
                newSocket = await sstpConnect(parsedSocks5Address, host, portNum, TCP连接);
                if (有效数据长度(本次首包数据) > 0) {
                    const writer = newSocket.writable.getWriter();
                    try { await writer.write(数据转Uint8Array(本次首包数据)) }
                    finally { try { writer.releaseLock() } catch (e) { } }
                }
            } else {
                log(`[反代连接] 代理到: ${host}:${portNum}`);
                const 所有反代数组 = await 解析地址端口(反代IP, host, yourUUID);
                newSocket = await connectProxyIP(`${查杀特征码}.tp1.090227.XyZ`, 1, 本次首包数据, 所有反代数组, 启用反代兜底);
            }
            if (本次发送首包) 已通过代理发送首包 = true;
            remoteConnWrapper.socket = newSocket;
            newSocket.closed.catch(() => { }).finally(() => closeSocketQuietly(ws));
            connectStreams(newSocket, ws, respHeader, null);
        })();

        remoteConnWrapper.connectingPromise = 当前连接任务;
        try {
            await 当前连接任务;
        } finally {
            if (remoteConnWrapper.connectingPromise === 当前连接任务) {
                remoteConnWrapper.connectingPromise = null;
            }
        }
    }
    remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

    if (启用SOCKS5反代 && (启用SOCKS5全局反代 || SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
        log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
        try {
            await connecttoPry();
        } catch (err) {
            log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${err.message}`);
            throw err;
        }
    } else {
        try {
            log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
            const initialSocket = await connectDirect(host, portNum, rawData, true);
            remoteConnWrapper.socket = initialSocket;
            connectStreams(initialSocket, ws, respHeader, async () => {
                if (remoteConnWrapper.socket !== initialSocket) return;
                await connecttoPry();
            });
        } catch (err) {
            log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
            if (err instanceof Error && err.name === '预加载解析为空') {
                closeSocketQuietly(ws);
                throw err;
            }
            await connecttoPry();
        }
    }
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null) {
    const 请求数据 = 数据转Uint8Array(udpChunk);
    const 请求字节数 = 请求数据.byteLength;
    log(`[UDP转发] 收到 DNS 请求: ${请求字节数}B -> 8.8.4.4:53`);
    try {
        const TCP连接 = 创建请求TCP连接器(request);
        const tcpSocket = TCP连接({ hostname: '8.8.4.4', port: 53 });
        let 魏烈思Header = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(请求数据);
        log(`[UDP转发] DNS 请求已写入上游: ${请求字节数}B`);
        writer.releaseLock();
        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                const 原始响应 = 数据转Uint8Array(chunk);
                log(`[UDP转发] 收到 DNS 响应: ${原始响应.byteLength}B`);
                const 封装结果 = 响应封装器 ? await 响应封装器(原始响应) : 原始响应;
                const 发送片段列表 = Array.isArray(封装结果) ? 封装结果 : [封装结果];
                if (!发送片段列表.length) return;
                if (webSocket.readyState !== WebSocket.OPEN) return;
                for (const fragment of 发送片段列表) {
                    const 转发响应 = 数据转Uint8Array(fragment);
                    if (!转发响应.byteLength) continue;
                    if (魏烈思Header) {
                        const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
                        response.set(魏烈思Header, 0);
                        response.set(转发响应, 魏烈思Header.length);
                        await WebSocket发送并等待(webSocket, response.buffer);
                        魏烈思Header = null;
                    } else {
                        await WebSocket发送并等待(webSocket, 转发响应);
                    }
                }
            },
        }));
    } catch (error) {
        log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
    }
}

export { 转发木马UDP数据, forwardataTCP, forwardataudp };
