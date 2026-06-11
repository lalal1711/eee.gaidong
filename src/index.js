/**
 * edgetunnel - Main Entry Point (ESM Module Structure)
 *
 * This file imports from src/*.js modules and re-exports the default
 * Cloudflare Worker fetch handler.
 *
 * Architecture:
 *   src/index.js          - Entry point: re-exports the fetch handler
 *   src/config.js         - Version, constants, global config
 *   src/crypto.js         - Cryptographic primitives (SHA, AES, ChaCha20, TLS utilities)
 *   src/utils.js          - Utility functions (DNS, logging, IP, config reader)
 *   src/tls.js            - TLS client implementation
 *   src/queue.js          - Upload queue, download grain sender
 *   src/ss.js             - Shadowsocks AEAD implementation
 *   src/proxy/forward.js  - TCP/UDP forwarding core
 *   src/proxy/socks5.js   - SOCKS5 proxy connector
 *   src/proxy/http.js     - HTTP/HTTPS proxy connector
 *   src/proxy/turn.js     - TURN proxy connector
 *   src/proxy/sstp.js     - SSTP proxy connector
 *   src/proxy/ws.js       - WebSocket proxy handler
 *   src/proxy/xhttp.js    - XHTTP proxy handler
 *   src/proxy/grpc.js     - gRPC proxy handler
 *   src/html.js           - HTML page generators (nginx, 1101)
 *   src/subscription.js   - Subscription generation (Clash, Sing-box, Surge)
 *   src/admin.js          - Admin panel API handlers
 */

// The source of truth is _worker.js which contains the complete working
// implementation. To build a unified deployment file, run:
//   node build.js
//
// This creates _worker.js from the src/ modules.
//
// For direct Cloudflare Workers deployment, use _worker.js directly.
export { default } from '../_worker.js';
