import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { Server } from '@modelcontextprotocol/server';
import { proxyServer, startHTTPServer } from 'mcp-proxy';
import { fileURLToPath } from 'node:url';

const port = Number(process.env.PERSONAL_CHROME_MCP_PORT || 18978);
const chromeMcp = fileURLToPath(new URL('./node_modules/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js', import.meta.url));
const client = new Client({ name: 'personal-chrome-gateway', version: '0.1.0' });
const transport = new StdioClientTransport({ command: process.execPath, args: [chromeMcp, '--autoConnect'], stderr: 'pipe' });

await client.connect(transport);
const capabilities = client.getServerCapabilities();
const serverVersion = client.getServerVersion();
const gateway = await startHTTPServer({
  host: '127.0.0.1',
  port,
  cors: false,
  sseEndpoint: null,
  createServer: async () => {
    const server = new Server(serverVersion, { capabilities });
    await proxyServer({ client, server, serverCapabilities: capabilities });
    return server;
  },
});

console.log(`Personal Chrome MCP listening at http://127.0.0.1:${port}/mcp`);
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, async () => {
    await gateway.close();
    await transport.close();
    process.exit(0);
  });
}
