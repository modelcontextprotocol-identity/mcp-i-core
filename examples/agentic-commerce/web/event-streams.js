/* One EventSource per endpoint across all monitor tabs. HTTP/1.1 browsers
 * otherwise exhaust their per-origin connection pool after six open monitors. */
const feeds = new Map();
const memberships = new Map();

function unsubscribe(port, url) {
  memberships.get(port)?.delete(url);
  const feed = feeds.get(url);
  if (!feed) return;
  feed.ports.delete(port);
  if (!feed.ports.size) {
    feed.source.close();
    feeds.delete(url);
  }
}

self.onconnect = ({ ports: [port] }) => {
  memberships.set(port, new Set());
  port.onmessage = ({ data }) => {
    if (!data || typeof data !== 'object') return;
    if (data.type === 'disconnect') {
      for (const url of memberships.get(port) || []) unsubscribe(port, url);
      memberships.delete(port);
      return;
    }
    const url = data.url;
    if (typeof url !== 'string') return;
    if (data.type === 'unsubscribe') { unsubscribe(port, url); return; }
    if (data.type !== 'subscribe' || memberships.get(port)?.has(url)) return;
    memberships.get(port)?.add(url);
    let feed = feeds.get(url);
    if (!feed) {
      const source = new EventSource(url);
      feed = { source, ports: new Set(), open: false };
      feeds.set(url, feed);
      const broadcast = (type, payload) => {
        for (const client of feed.ports) client.postMessage({ url, type, data: payload });
      };
      source.onopen = () => { feed.open = true; broadcast('open'); };
      source.onerror = () => { feed.open = false; broadcast('error'); };
      source.onmessage = event => broadcast('message', event.data);
    }
    feed.ports.add(port);
    if (feed.open) port.postMessage({ url, type: 'open' });
  };
  port.start();
};
