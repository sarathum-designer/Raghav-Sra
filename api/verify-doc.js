// Approves or rejects a single document (admin only).
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

    const doc_id = req.body?.doc_id || '';
    const action = req.body?.action || '';
    const notes  = sanitize(req.body?.notes || '', 500);

    if (!doc_id || !['approved', 'rejected'].includes(action))
      return res.status(400).json({ error: 'doc_id and action (approved/rejected) are required.' });

    const { data: doc, error: fetchErr } = await supabase
      .from('documents')
      .select('id, owner_id, doc_type')
      .eq('id', doc_id)
      .single();

    if (fetchErr || !doc)
      return res.status(404).json({ error: 'Document not found.' });

    const { error: updateErr } = await supabase
      .from('documents')
      .update({ status: action, review_notes: notes || null })
      .eq('id', doc_id);

    if (updateErr)
      return res.status(500).json({ error: 'Database error. Please try again.' });

    await writeAuditLog(`doc_${action}`, payload.id, 'admin', doc_id,
      { doc_type: doc.doc_type, owner_id: doc.owner_id, notes }, getIP(req));

    return res.status(200).json({ ok: true, status: action });

  } catch (err) {
    console.error('verify-doc error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
