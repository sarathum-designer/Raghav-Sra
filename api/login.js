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
    const ip = getIP(req);
    const houseId  = sanitize(req.body?.house_id  || '', 20).toUpperCase();
    const password = sanitize(req.body?.password  || '', 128);

    if (!houseId || !password)
      return res.status(400).json({ error: 'House ID and password are required.' });

    if (!/^NAL-\d{3,6}$/.test(houseId))
      return res.status(400).json({ error: 'Invalid House ID format.' });

    if (await isRateLimited(houseId)) {
      await writeAuditLog('login_blocked', null, 'owner', null, { house_id: houseId }, ip);
      return res.status(429).json({ error: 'Too many failed attempts. Try again after 15 minutes.' });
    }

    const { data: owner, error } = await supabase
      .from('owners')
      .select('id, house_id, name, phone, email, verified, rejection_notes, password_hash')
      .eq('house_id', houseId)
      .single();

    const dummyHash = '$2a$10$invalidhashpadding000000000000000000000000000000000000';
    const match = await bcrypt.compare(password, owner?.password_hash || dummyHash);

    if (error || !owner || !match) {
      await recordAttempt(houseId, ip, false);
      await writeAuditLog('login_failed', null, 'owner', null, { house_id: houseId }, ip);
      return res.status(401).json({ error: 'Invalid House ID or password.' });
    }

    await clearAttempts(houseId);
    await writeAuditLog('login_success', owner.id, 'owner', null, { house_id: houseId }, ip);

    const token = jwt.sign(
      { id: owner.id, house_id: owner.house_id, role: 'owner' },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const { password_hash: _, ...safeOwner } = owner;
    return res.status(200).json({ token, owner: safeOwner });

  } catch (err) {
    console.error('login error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
