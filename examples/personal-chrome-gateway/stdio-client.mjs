import { ServerType, startStdioServer } from 'mcp-proxy';

const port = Number(process.env.PERSONAL_CHROME_MCP_PORT || 18978);
await startStdioServer({
  serverType: ServerType.HTTPStream,
  url: `http://127.0.0.1:${port}/mcp`,
});
