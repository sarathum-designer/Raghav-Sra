// Generates a short-lived signed upload URL so the browser can upload
// directly to Supabase Storage — no file bytes pass through Vercel.
const supabase = require('./_client');
const { verifyToken, validateMagicBytes, sanitize, writeAuditLog, getIP } = require('./_security');

const ALLOWED_TYPES = ['govt_id', 'ownership_doc', 'tax_bill', 'utility_bill'];
const ALLOWED_MIME  = ['image/jpeg', 'image/png', 'application/pdf'];
const MAX_BYTES     = 8 * 1024 * 1024; // 8 MB

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'owner');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const doc_type    = sanitize(req.body?.doc_type    || '', 30);
    const file_name   = sanitize(req.body?.file_name   || '', 255);
    const mime_type   = sanitize(req.body?.mime_type   || '', 50);
    const file_size   = Number(req.body?.file_size)    || 0;
    const file_header = req.body?.file_header          || ''; // base64 of first 32 bytes

    if (!ALLOWED_TYPES.includes(doc_type))
      return res.status(400).json({ error: 'Invalid document type.' });
    if (!ALLOWED_MIME.includes(mime_type))
      return res.status(400).json({ error: 'Only PDF, JPG, and PNG files are allowed.' });
    if (file_size > MAX_BYTES)
      return res.status(400).json({ error: 'File exceeds 8 MB limit.' });

    // Validate magic bytes from the first 32 bytes sent by the client
    if (file_header) {
      const headerBuf = Buffer.from(file_header, 'base64');
      if (!validateMagicBytes(headerBuf, mime_type)) {
        await writeAuditLog('upload_magic_bytes_fail', payload.id, 'owner', null,
          { doc_type, file_name, mime_type }, getIP(req));
        return res.status(400).json({ error: 'File content does not match declared type.' });
      }
    }

    const ext      = mime_type === 'image/jpeg' ? 'jpg' : mime_type === 'image/png' ? 'png' : 'pdf';
    const safePath = `${payload.id}/${doc_type}_${Date.now()}.${ext}`;

    // Create a signed upload URL (expires in 60 seconds — enough for upload)
    const { data, error } = await supabase.storage
      .from('documents')
      .createSignedUploadUrl(safePath);

    if (error || !data?.signedUrl)
      return res.status(500).json({ error: 'Could not generate upload URL. Please try again.' });

    return res.status(200).json({ upload_url: data.signedUrl, file_path: safePath });

  } catch (err) {
    console.error('upload-url error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
