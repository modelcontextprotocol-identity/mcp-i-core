import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

export function registerSigIntHandler(
  transports: Map<string, StdioServerTransport | StreamableHTTPServerTransport>
) {
  process.on('SIGINT', async () => {
    for (const sessionID of transports.keys()) {
      await transports.get(sessionID)?.close();
      transports.delete(sessionID);
    }

    console.error('Server shut down.');
    process.exit(0);
  });
}
