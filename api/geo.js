export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { src, ip } = req.query;
  if (src !== 'iplocate') return res.status(400).json({ error: 'Missing or unknown src parameter' });
  if (!ip) return res.status(400).json({ error: 'Missing ip' });
  if (!/^[0-9a-fA-F:.]{2,45}$/.test(ip)) return res.status(400).json({ error: 'Invalid IP' });

  const apiKey = process.env.IPLOCATE_API_KEY;
  const headers = { 'Accept': 'application/json' };
  if (apiKey) headers['x-api-key'] = apiKey;

  try {
    const upstream = await fetch(`https://www.iplocate.io/api/lookup/${encodeURIComponent(ip)}`, {
      headers: { 'User-Agent': 'x-verdikt/1.0', ...headers },
      signal: AbortSignal.timeout(8000),
    });
    if (upstream.status === 404) return res.status(404).json({ error: 'Not found' });
    if (upstream.status === 429) return res.status(429).json({ error: 'IPLocate rate limit' });
    if (!upstream.ok) return res.status(502).json({ error: `IPLocate returned ${upstream.status}` });
    let data;
    try { data = await upstream.json(); }
    catch (_) { return res.status(502).json({ error: 'IPLocate returned non-JSON response' }); }
    return res.status(200).json(data);
  } catch (e) {
    const isTimeout = e.name === 'TimeoutError' || e.name === 'AbortError';
    return res.status(isTimeout ? 504 : 502).json({
      error: isTimeout ? 'IPLocate timed out' : 'Upstream request failed',
      detail: e.message,
    });
  }
}
