function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Non authentifié. Veuillez vous connecter.' });
  }
  next();
}

function requireGuest(req, res, next) {
  if (req.session?.userId) {
    return res.redirect('/dashboard');
  }
  next();
}

module.exports = { requireAuth, requireGuest };
