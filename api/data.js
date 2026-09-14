import { kv } from '@vercel/kv';

const DATA_KEY = 'rsts:site-data';
const SECRET_KEY = 'rsts:admin-secret';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  try {
    if (req.method === 'GET') {
      const data = await kv.get(DATA_KEY);
      return res.status(200).json({ data: data || null });
    }

    if (req.method === 'POST') {
      const action = req.query.action || 'save';
      const password = req.headers['x-admin-pass'];

      if (!password || typeof password !== 'string' || password.length < 4) {
        return res.status(401).json({ error: 'password required' });
      }

      let secret = await kv.get(SECRET_KEY);

      if (action === 'verify') {
        if (!secret) {
          await kv.set(SECRET_KEY, password);
          return res.status(200).json({ ok: true, bootstrapped: true });
        }
        if (password !== secret) return res.status(403).json({ error: 'wrong password' });
        return res.status(200).json({ ok: true });
      }

      if (action === 'change-password') {
        if (!secret) {
          await kv.set(SECRET_KEY, password);
          return res.status(200).json({ ok: true, bootstrapped: true });
        }
        if (password !== secret) return res.status(403).json({ error: 'wrong password' });
        const { newPassword } = req.body || {};
        if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 4) {
          return res.status(400).json({ error: 'invalid new password' });
        }
        await kv.set(SECRET_KEY, newPassword);
        return res.status(200).json({ ok: true });
      }

      if (!secret) {
        await kv.set(SECRET_KEY, password);
        secret = password;
      }
      if (password !== secret) return res.status(403).json({ error: 'wrong password' });

      const body = req.body;
      if (!body || typeof body !== 'object') {
        return res.status(400).json({ error: 'invalid body' });
      }
      await kv.set(DATA_KEY, body);
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST');
    return res.status(405).json({ error: 'method not allowed' });
  } catch (err) {
    return res.status(500).json({ error: 'kv_error', message: String(err && err.message || err) });
  }
}
