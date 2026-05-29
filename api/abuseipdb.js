export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'ABUSEIPDB_API_KEY not configured' });

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip parameter' });
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return res.status(400).json({ error: 'Invalid IP format' });

  try {
    const upstream = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      { headers: { 'Key': apiKey, 'Accept': 'application/json' } }
    );
    const data = await upstream.json();
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream request failed', detail: e.message });
  }
}
