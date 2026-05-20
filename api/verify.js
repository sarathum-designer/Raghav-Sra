const supabase = require('./_client');
const { verifyToken, writeAuditLog, sanitize, getIP } = require('./_security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIP(req);
  const { payload, error: authErr, status: authStatus } = verifyToken(req, 'admin');
  if (authErr) return res.status(authStatus).json({ error: authErr });

  const owner_id = sanitize(req.body?.owner_id || '', 40);
  const action   = sanitize(req.body?.action   || '', 10);
  const notes    = sanitize(req.body?.notes    || '', 500);

  if (!owner_id || !['approve', 'reject'].includes(action))
    return res.status(400).json({ error: 'owner_id and action (approve|reject) are required.' });

  const isApproved = action === 'approve';

  const { data, error } = await supabase
    .from('owners')
    .update({
      verified:         isApproved,
      verified_at:      isApproved ? new Date().toISOString() : null,
      rejection_notes:  isApproved ? null : (notes || 'Documents rejected by Raghav Realty.')
    })
    .eq('id', owner_id)
    .select('id, house_id, name, verified')
    .single();

  if (error) return res.status(500).json({ error: 'Database update failed.' });

  await supabase
    .from('documents')
    .update({
      status:       isApproved ? 'approved' : 'rejected',
      review_notes: notes || null,
      reviewed_at:  new Date().toISOString()
    })
    .eq('owner_id', owner_id);

  // Audit log
  await writeAuditLog(
    isApproved ? 'owner_approved' : 'owner_rejected',
    payload.id, 'admin', owner_id,
    { house_id: data.house_id, notes: notes || null }, ip
  );

  return res.status(200).json({ success: true, owner: data });
};
