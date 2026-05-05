export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const targetUrl = 'http://152.69.200.74:8080' + url.pathname + url.search;
      const newHeaders = new Headers(request.headers);
      newHeaders.delete('Cookie');
      newHeaders.delete('Authorization');
      return fetch(targetUrl, {
        method: request.method,
        headers: newHeaders,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });
    }
    return env.ASSETS.fetch(request);
  }
}
