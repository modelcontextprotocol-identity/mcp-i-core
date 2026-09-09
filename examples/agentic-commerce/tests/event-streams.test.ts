import fs from 'node:fs';
import vm from 'node:vm';
import { describe, expect, it } from 'vitest';

function workerHarness() {
  const streams: { url: string; closed: boolean; onmessage?: (event: { data: string }) => void; close(): void }[] = [];
  const context = vm.createContext({
    EventSource: class {
      closed = false;
      constructor(public url: string) { streams.push(this); }
      close() { this.closed = true; }
    },
  });
  context.self = context;
  vm.runInContext(fs.readFileSync('web/event-streams.js', 'utf8'), context);
  function client() {
    const messages: unknown[] = [];
    const port = { postMessage: (message: unknown) => messages.push(message), start() {}, onmessage: null as null | ((event: { data: unknown }) => void) };
    context.onconnect({ ports: [port] });
    return { messages, send: (data: unknown) => port.onmessage!({ data }) };
  }
  return { streams, client };
}

describe('shared monitor event connections', () => {
  it('shares one stream across tabs and fans events out without opening extra sockets', () => {
    const w = workerHarness();
    const tabs = Array.from({ length: 8 }, () => w.client());
    for (const tab of tabs) tab.send({ type: 'subscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams).toHaveLength(1);
    w.streams[0]!.onmessage!({ data: '{"type":"request"}' });
    for (const tab of tabs) expect(tab.messages).toContainEqual({ url: 'http://localhost:4949/api/events', type: 'message', data: '{"type":"request"}' });
    tabs[0]!.send({ type: 'unsubscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams[0]!.closed).toBe(false);
    for (const tab of tabs.slice(1)) tab.send({ type: 'unsubscribe', url: 'http://localhost:4949/api/events' });
    expect(w.streams[0]!.closed).toBe(true);
  });

  it('keeps merchant and RP feeds independent and ignores duplicate subscriptions', () => {
    const w = workerHarness(), tab = w.client();
    for (const url of ['http://localhost:4949/api/events', 'http://localhost:4950/api/rp/events', 'http://localhost:4949/api/events']) tab.send({ type: 'subscribe', url });
    expect(w.streams).toHaveLength(2);
    tab.send({ type: 'disconnect' });
    expect(w.streams.every(stream => stream.closed)).toBe(true);
  });
});
