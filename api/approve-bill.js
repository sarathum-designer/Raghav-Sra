// Admin: approves or rejects a bill claim.
const supabase = require('./_client');
const { verifyToken, sanitize, writeAuditLog, getIP } = require('./_security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'admin');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const bill_id = req.body?.bill_id || '';
    const action  = req.body?.action  || '';
    const notes   = sanitize(req.body?.notes || '', 500);

    if (!bill_id || !['approved', 'rejected'].includes(action))
      return res.status(400).json({ error: 'bill_id and action (approved/rejected) are required.' });

    const { data: bill, error: fetchErr } = await supabase
      .from('bill_claims')
      .select('id, owner_id, bill_type, bill_month')
      .eq('id', bill_id)
      .single();

    if (fetchErr || !bill)
      return res.status(404).json({ error: 'Bill claim not found.' });

    const updateFields = {
      status: action,
      notes:  notes || null,
      ...(action === 'approved' ? { approved_at: new Date().toISOString() } : {})
    };

    const { error: updateErr } = await supabase
      .from('bill_claims')
      .update(updateFields)
      .eq('id', bill_id);

    if (updateErr)
      return res.status(500).json({ error: 'Database error.' });

    await writeAuditLog(`bill_${action}`, payload.id, 'admin', bill_id,
      { bill_type: bill.bill_type, bill_month: bill.bill_month, owner_id: bill.owner_id, notes }, getIP(req));

    return res.status(200).json({ ok: true, status: action });

  } catch (err) {
    console.error('approve-bill error:', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
};
