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
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'admin');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const { data: owners, error } = await supabase
      .from('owners')
      .select('id, house_id, name, phone, email, verified, verified_at, rejection_notes, created_at')
      .order('house_id', { ascending: true });

    if (error) return res.status(500).json({ error: 'Database error.' });

    const { data: allDocs } = await supabase
      .from('documents')
      .select('id, owner_id, doc_type, file_name, file_path, status, review_notes, uploaded_at');

    const docsWithUrls = await Promise.all(
      (allDocs || []).map(async (doc) => {
        const { data } = await supabase.storage
          .from('documents')
          .createSignedUrl(doc.file_path, SIGNED_URL_TTL);
        const { file_path: _, ...rest } = doc;
        return { ...rest, file_url: data?.signedUrl || null };
      })
    );

    const docsByOwner = {};
    docsWithUrls.forEach(d => {
      if (!docsByOwner[d.owner_id]) docsByOwner[d.owner_id] = [];
      docsByOwner[d.owner_id].push(d);
    });

    return res.status(200).json({
      owners: (owners || []).map(o => ({ ...o, documents: docsByOwner[o.id] || [] }))
    });

  } catch (err) {
    console.error('owners error:', err.message);
    return res.status(500).json({ error: 'Server error. Please try again.' });
  }
};
