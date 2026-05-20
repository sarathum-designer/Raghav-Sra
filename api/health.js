// Quick health-check — no DB, no env vars needed.
// Visit /api/health to confirm Vercel serverless functions are running.
module.exports = (req, res) => {
  res.status(200).json({ ok: true, ts: new Date().toISOString() });
};
