const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'https://nimzcwbdjvzqqdzeqfju.supabase.co';

// Do NOT throw at module level — Vercel can't catch it and returns an HTML error page.
// Individual routes will get a 500 JSON response if the key is missing.
const supabase = createClient(
  SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || '',
  { auth: { persistSession: false } }
);

module.exports = supabase;
