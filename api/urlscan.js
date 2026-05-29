export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  const headers = { 'Accept': 'application/json' };
  if (process.env.URLSCAN_API_KEY) headers['API-Key'] = process.env.URLSCAN_API_KEY;

  try {
    const upstream = await fetch(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=20`,
      { headers }
    );
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
