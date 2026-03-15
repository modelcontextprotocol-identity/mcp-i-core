import newMcpServer from '../server.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

const createTransport = (): StdioServerTransport => {
  return new StdioServerTransport();
};

const start = async (): Promise<void> => {
  const transport = createTransport();
  const mcpServer = await newMcpServer();
  await mcpServer.connect(transport);
};

export default { start, createTransport };
