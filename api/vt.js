export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'VT_API_KEY not configured' });

  const { path } = req.query;
  if (!path) return res.status(400).json({ error: 'Missing path parameter' });

  const decodedPath = decodeURIComponent(path);
  const allowed = ['/api/v3/ip_addresses/', '/api/v3/domains/', '/api/v3/urls/', '/api/v3/files/'];
  if (!allowed.some(p => decodedPath.startsWith(p))) {
    return res.status(400).json({ error: 'Endpoint not allowed' });
  }

  try {
    const upstream = await fetch(`https://www.virustotal.com${decodedPath}`, {
      headers: { 'x-apikey': apiKey },
    });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
