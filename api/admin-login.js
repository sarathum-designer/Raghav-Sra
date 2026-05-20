const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const supabase = require('./_client');
const { isRateLimited, recordAttempt, clearAttempts, writeAuditLog, sanitize, getIP } = require('./_security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const ip       = getIP(req);
    const password = sanitize(req.body?.password || '', 128);
    if (!password) return res.status(400).json({ error: 'Password is required.' });

    const rateLimitKey = `admin_${ip}`;
    if (await isRateLimited(rateLimitKey)) {
      await writeAuditLog('admin_login_blocked', null, 'admin', null, {}, ip);
      return res.status(429).json({ error: 'Too many failed attempts. Try again after 15 minutes.' });
    }

    const { data: admin, error } = await supabase
      .from('admins')
      .select('id, username, display_name, password_hash')
      .limit(1)
      .single();

    const dummyHash = '$2a$10$invalidhashpadding000000000000000000000000000000000000';
    const match = await bcrypt.compare(password, admin?.password_hash || dummyHash);

    if (error || !admin || !match) {
      await recordAttempt(rateLimitKey, ip, false);
      await writeAuditLog('admin_login_failed', null, 'admin', null, {}, ip);
      return res.status(401).json({ error: 'Incorrect password.' });
    }

    await clearAttempts(rateLimitKey);
    await writeAuditLog('admin_login_success', admin.id, 'admin', null, {}, ip);

    const token = jwt.sign(
      { id: admin.id, role: 'admin', name: admin.display_name },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    return res.status(200).json({ token, name: admin.display_name });

  } catch (err) {
    console.error('admin-login error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
