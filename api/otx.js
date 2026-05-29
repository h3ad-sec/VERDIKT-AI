export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'OTX_API_KEY not configured' });

  const { path } = req.query;
  if (!path) return res.status(400).json({ error: 'Missing path parameter' });

  const decodedPath = decodeURIComponent(path);
  const allowed = [
    '/api/v1/indicators/IPv4/', '/api/v1/indicators/IPv6/',
    '/api/v1/indicators/domain/', '/api/v1/indicators/url/',
    '/api/v1/indicators/file/', '/api/v1/indicators/ASN/',
  ];
  if (!allowed.some(p => decodedPath.startsWith(p))) {
    return res.status(400).json({ error: 'Endpoint not allowed' });
  }

  try {
    const upstream = await fetch(`https://otx.alienvault.com${decodedPath}`, {
      headers: { 'X-OTX-API-KEY': apiKey },
    });
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
