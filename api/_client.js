// Shared Supabase client — used by all API routes.
// Files prefixed with _ are NOT exposed as Vercel endpoints.
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'https://nimzcwbdjvzqqdzeqfju.supabase.co';

if (!process.env.SUPABASE_SERVICE_KEY) {
  throw new Error('Missing env var: SUPABASE_SERVICE_KEY');
}

const supabase = createClient(SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
});

module.exports = supabase;
