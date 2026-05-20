// Admin: returns all bill claims joined with owner info + fresh signed URLs.
const supabase = require('./_client');
const { verifyToken } = require('./_security');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET')    return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { payload, error: authErr, status: authStatus } = verifyToken(req, 'admin');
    if (authErr) return res.status(authStatus).json({ error: authErr });

    const { data: bills, error: dbErr } = await supabase
      .from('bill_claims')
      .select(`
        *,
        owners ( id, house_id, name, phone )
      `)
      .order('created_at', { ascending: false });

    if (dbErr)
      return res.status(500).json({ error: 'Database error.' });

    const billsWithUrls = await Promise.all((bills || []).map(async (b) => {
      if (!b.file_path) return b;
      const { data } = await supabase.storage.from('documents').createSignedUrl(b.file_path, 3600);
      return { ...b, file_url: data?.signedUrl || null };
    }));

    return res.status(200).json({ bills: billsWithUrls });

  } catch (err) {
    console.error('admin-bills error:', err.message);
    return res.status(500).json({ error: 'Server error.' });
  }
};
