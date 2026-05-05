export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      const targetUrl = 'http://152.69.200.74:8080' + url.pathname + url.search;
      return fetch(targetUrl, {
        method: request.method,
        headers: request.headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      });
    }
    if (url.pathname.startsWith('/job/')) {
      url.pathname = '/job.html';
      return env.ASSETS.fetch(url.toString());
    }
    return env.ASSETS.fetch(request);
  }
}
