const supabase = require('./_client');
const { verifyToken } = require('./_security');

const SIGNED_URL_TTL = 60 * 60; // 1 hour

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET')    return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'owner');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const { data: owner, error } = await supabase
      .from('owners')
      .select('id, house_id, name, phone, email, verified, rejection_notes, created_at')
      .eq('id', payload.id)
      .single();

    if (error || !owner) return res.status(404).json({ error: 'Owner not found.' });

    const { data: documents } = await supabase
      .from('documents')
      .select('id, doc_type, file_name, file_path, status, review_notes, uploaded_at')
      .eq('owner_id', owner.id)
      .order('uploaded_at', { ascending: false });

    const docsWithUrls = await Promise.all(
      (documents || []).map(async (doc) => {
        const { data } = await supabase.storage
          .from('documents')
          .createSignedUrl(doc.file_path, SIGNED_URL_TTL);
        const { file_path: _, ...rest } = doc;
        return { ...rest, file_url: data?.signedUrl || null };
      })
    );

    return res.status(200).json({ owner, documents: docsWithUrls });

  } catch (err) {
    console.error('me error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
