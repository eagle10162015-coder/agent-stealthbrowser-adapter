# Persistent personal Chrome MCP gateway

This example keeps one [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) auto-connect session open and shares it with multiple MCP clients through [mcp-proxy](https://github.com/punkpeye/mcp-proxy). It connects to Chrome's active default profile, so agents can work in already signed-in tabs. Browser input stays inside Chrome; it does not send operating-system mouse or keyboard events.

1. Install dependencies in this directory with `npm install`.
2. In Chrome 144 or later, open `chrome://inspect/#remote-debugging` and enable remote debugging.
3. Run `node gateway.mjs`. The HTTP endpoint binds to `127.0.0.1:18978/mcp` by default. Set `PERSONAL_CHROME_MCP_PORT` for another port.
4. When the first browser tool call requests access, allow Chrome's permission dialog. The running gateway reuses that connection for later clients. Chrome can ask again after the gateway or browser restarts.
5. Point HTTP-capable MCP clients at the endpoint. For a stdio-only client, run `node stdio-client.mjs` as its MCP command.

The gateway does not select among multiple Chrome profiles. Chrome DevTools MCP currently attaches to the default active profile. Agents should create background tabs when they need to avoid taking focus from the user's active tab. A background tab still belongs to the same browser profile and should be closed after the task.

The endpoint is local only and CORS is disabled. Any local process with access to the endpoint can use the signed-in Chrome profile while the gateway is running. Review which agents and programs run on the machine before enabling it.
