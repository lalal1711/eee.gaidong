/**
 * edgetunnel build script
 * Combines src/*.js modules into a single _worker.js for deployment.
 *
 * Usage: node build.js
 *
 * This creates _worker.js in the project root.
 * The modules import each other via ES module syntax and the build
 * script inlines them into a single file.
 */

const fs = require('fs');
const path = require('path');

const SRC = __dirname;
const OUTPUT = path.join(SRC, '_worker.js');
const BANNER = `// edgetunnel v2.1 - Built from src/ modules
// Source: https://github.com/lalal1711/edgetunnel.gaidong
// Build time: ${new Date().toISOString()}

`;

// Ordered list of module files to concatenate (order matters for dependencies)
const MODULES = [
  'src/config.js',
  'src/crypto.js',
  'src/utils.js',
  'src/queue.js',
  'src/tls.js',
  'src/ss.js',
  'src/proxy/forward.js',
  'src/proxy/socks5.js',
  'src/proxy/http.js',
  'src/proxy/turn.js',
  'src/proxy/sstp.js',
  'src/proxy/ws.js',
  'src/proxy/xhttp.js',
  'src/proxy/grpc.js',
  'src/html.js',
  'src/subscription.js',
  'src/admin.js',
];

function build() {
  const parts = [BANNER];

  for (const mod of MODULES) {
    const fullPath = path.join(SRC, mod);
    if (!fs.existsSync(fullPath)) {
      console.warn(`[WARN] Module not found: ${mod} - skipping`);
      continue;
    }

    let content = fs.readFileSync(fullPath, 'utf-8');

    // Remove ES module imports (they'll be resolved by ordering)
    content = content.replace(/^import\s+.*?from\s+['"].*?['"];?\s*$/gm, '');
    content = content.replace(/^import\s+['"].*?['"];?\s*$/gm, '');

    // Convert exports to plain declarations
    // export function -> function
    content = content.replace(/^export\s+function\s+/gm, 'function ');
    // export const -> const
    content = content.replace(/^export\s+const\s+/gm, 'const ');
    // export let -> let
    content = content.replace(/^export\s+let\s+/gm, 'let ');
    // export async function -> async function
    content = content.replace(/^export\s+async\s+function\s+/gm, 'async function ');
    // export class -> class
    content = content.replace(/^export\s+class\s+/gm, 'class ');
    // export { ... } - side-effect exports (re-exports), remove
    content = content.replace(/^export\s+\{[^}]+\};?\s*$/gm, '');

    parts.push(`// ===== Module: ${mod} =====\n${content}\n`);
  }

  // Add the main export
  parts.push(`// ===== Main entry point =====
export default {
  async fetch(request, env, ctx) {
    return await handleRequest(request, env, ctx);
  }
};
`);

  const result = parts.join('\n');
  fs.writeFileSync(OUTPUT, result, 'utf-8');
  console.log(`Built: ${OUTPUT} (${result.length} bytes, ${result.split('\\n').length} lines)`);
}

build();
