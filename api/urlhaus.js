export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host, url, sha256, md5 } = req.query;

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (process.env.ABUSECH_AUTH_KEY) headers['Auth-Key'] = process.env.ABUSECH_AUTH_KEY;

  try {
    let endpoint, formBody;

    if (host) {
      if (!host || host.length > 253)
        return res.status(400).json({ error: 'Invalid host format' });
      endpoint = 'https://urlhaus-api.abuse.ch/v1/host/';
      formBody = new URLSearchParams({ host });

    } else if (url) {
      if (!/^https?:\/\/.{1,2000}/.test(url))
        return res.status(400).json({ error: 'Invalid URL format' });
      endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
      formBody = new URLSearchParams({ url });

    } else if (sha256) {
      if (!/^[0-9a-fA-F]{64}$/.test(sha256))
        return res.status(400).json({ error: 'Invalid SHA256 format' });
      endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
      formBody = new URLSearchParams({ sha256_hash: sha256 });

    } else if (md5) {
      if (!/^[0-9a-fA-F]{32}$/.test(md5))
        return res.status(400).json({ error: 'Invalid MD5 format' });
      endpoint = 'https://urlhaus-api.abuse.ch/v1/payload/';
      formBody = new URLSearchParams({ md5_hash: md5 });

    } else {
      return res.status(400).json({ error: 'Missing parameter: host, url, sha256, or md5' });
    }

    const upstream = await fetch(endpoint, { method: 'POST', headers, body: formBody });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
