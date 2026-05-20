// Called after the browser has finished uploading directly to Supabase Storage.
// Records the document in the DB and cleans up any previous upload for the same type.
const supabase = require('./_client');
const { verifyToken, sanitize, writeAuditLog, getIP } = require('./_security');

const ALLOWED_TYPES = ['govt_id', 'ownership_doc', 'tax_bill', 'utility_bill'];

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'owner');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const file_path = sanitize(req.body?.file_path || '', 255);
    const file_name = sanitize(req.body?.file_name || '', 255);
    const doc_type  = sanitize(req.body?.doc_type  || '', 30);

    if (!file_path || !file_name || !ALLOWED_TYPES.includes(doc_type))
      return res.status(400).json({ error: 'Missing required fields.' });

    // Ensure the path actually belongs to this owner (prevent path injection)
    if (!file_path.startsWith(`${payload.id}/`))
      return res.status(403).json({ error: 'Invalid file path.' });

    // Remove previous upload of the same type
    const { data: oldDoc } = await supabase.from('documents')
      .select('file_path').eq('owner_id', payload.id).eq('doc_type', doc_type).single();
    if (oldDoc?.file_path) {
      await supabase.storage.from('documents').remove([oldDoc.file_path]);
    }
    await supabase.from('documents').delete()
      .eq('owner_id', payload.id).eq('doc_type', doc_type);

    // Insert new record (signed URL generated on-demand when needed)
    const { data: doc, error: dbErr } = await supabase.from('documents')
      .insert({ owner_id: payload.id, doc_type, file_name, file_path, file_url: null, status: 'pending' })
      .select().single();

    if (dbErr)
      return res.status(500).json({ error: 'Database error. Please try again.' });

    await writeAuditLog('doc_uploaded', payload.id, 'owner', doc.id,
      { doc_type, file_name }, getIP(req));

    return res.status(200).json({ document: doc });

  } catch (err) {
    console.error('confirm-upload error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
