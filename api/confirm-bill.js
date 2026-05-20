// Called after the browser finishes uploading a bill directly to Supabase Storage.
// Records the bill claim in the DB.
const supabase = require('./_client');
const { verifyToken, sanitize, writeAuditLog, getIP } = require('./_security');

const BILL_TYPES = ['electricity', 'gas', 'water', 'other'];

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'owner');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const file_path    = sanitize(req.body?.file_path   || '', 255);
    const file_name    = sanitize(req.body?.file_name   || '', 255);
    const bill_type    = sanitize(req.body?.bill_type   || '', 20);
    const bill_month   = sanitize(req.body?.bill_month  || '', 20);
    const raw_amount   = req.body?.claim_amount;
    const claim_amount = raw_amount != null && raw_amount !== '' ? parseFloat(raw_amount) : null;

    if (!file_path || !file_name || !BILL_TYPES.includes(bill_type) || !bill_month)
      return res.status(400).json({ error: 'Missing or invalid fields.' });

    if (!file_path.startsWith(`${payload.id}/`))
      return res.status(403).json({ error: 'Invalid file path.' });

    if (claim_amount !== null && (isNaN(claim_amount) || claim_amount < 0 || claim_amount > 999999))
      return res.status(400).json({ error: 'Invalid claim amount.' });

    const { data: bill, error: dbErr } = await supabase
      .from('bill_claims')
      .insert({
        owner_id: payload.id,
        bill_type,
        bill_month,
        claim_amount,
        file_name,
        file_path,
        file_url: null,
        status: 'pending'
      })
      .select()
      .single();

    if (dbErr)
      return res.status(500).json({ error: 'Database error. Please try again.' });

    await writeAuditLog('bill_submitted', payload.id, 'owner', bill.id,
      { bill_type, bill_month, claim_amount }, getIP(req));

    return res.status(200).json({ bill });

  } catch (err) {
    console.error('confirm-bill error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
