const supabase = require('./_client');
const { verifyToken, validateMagicBytes, writeAuditLog, sanitize, getIP } = require('./_security');

const ALLOWED_TYPES = ['govt_id', 'ownership_doc', 'tax_bill', 'utility_bill'];
const ALLOWED_MIME  = ['image/jpeg', 'image/png', 'application/pdf'];
const MAX_BYTES     = 8 * 1024 * 1024;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const ip = getIP(req);
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'owner');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const doc_type    = sanitize(req.body?.doc_type   || '', 30);
    const file_name   = sanitize(req.body?.file_name  || '', 255);
    const mime_type   = sanitize(req.body?.mime_type  || '', 50);
    const file_base64 = req.body?.file_base64;

    if (!ALLOWED_TYPES.includes(doc_type))
      return res.status(400).json({ error: 'Invalid document type.' });
    if (!file_base64 || typeof file_base64 !== 'string')
      return res.status(400).json({ error: 'File data is required.' });
    if (!ALLOWED_MIME.includes(mime_type))
      return res.status(400).json({ error: 'Only PDF, JPG, and PNG files are allowed.' });

    const safeFileName = file_name.replace(/[^a-zA-Z0-9._\- ]/g, '_').replace(/\.{2,}/g, '_');
    if (!safeFileName) return res.status(400).json({ error: 'Invalid file name.' });

    let buffer;
    try { buffer = Buffer.from(file_base64, 'base64'); }
    catch { return res.status(400).json({ error: 'Invalid file encoding.' }); }

    if (buffer.length === 0)        return res.status(400).json({ error: 'File is empty.' });
    if (buffer.length > MAX_BYTES)  return res.status(400).json({ error: 'File exceeds 8 MB limit.' });

    if (!validateMagicBytes(buffer, mime_type)) {
      await writeAuditLog('upload_magic_bytes_fail', payload.id, 'owner', null,
        { doc_type, file_name: safeFileName, mime_type }, ip);
      return res.status(400).json({ error: 'File content does not match declared type. Please upload a genuine PDF, JPG, or PNG.' });
    }

    const ext      = mime_type === 'image/jpeg' ? 'jpg' : mime_type === 'image/png' ? 'png' : 'pdf';
    const safePath = `${payload.id}/${doc_type}_${Date.now()}.${ext}`;

    const { error: uploadErr } = await supabase.storage
      .from('documents')
      .upload(safePath, buffer, { contentType: mime_type, upsert: false });

    if (uploadErr)
      return res.status(500).json({ error: 'Storage upload failed. Please try again.' });

    // Remove old file & record if re-uploading
    const { data: oldDoc } = await supabase.from('documents')
      .select('file_path').eq('owner_id', payload.id).eq('doc_type', doc_type).single();
    if (oldDoc?.file_path) await supabase.storage.from('documents').remove([oldDoc.file_path]);
    await supabase.from('documents').delete().eq('owner_id', payload.id).eq('doc_type', doc_type);

    const { data: doc, error: dbErr } = await supabase
      .from('documents')
      .insert({ owner_id: payload.id, doc_type, file_name: safeFileName, file_path: safePath, file_url: null, status: 'pending' })
      .select().single();

    if (dbErr) return res.status(500).json({ error: 'Database error. Please try again.' });

    await writeAuditLog('doc_uploaded', payload.id, 'owner', doc.id, { doc_type, file_name: safeFileName }, ip);
    return res.status(200).json({ document: doc });

  } catch (err) {
    console.error('upload error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};

module.exports.config = { api: { bodyParser: { sizeLimit: '12mb' } } };
