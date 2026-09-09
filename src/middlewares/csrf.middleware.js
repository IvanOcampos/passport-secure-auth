const crypto = require('crypto');

function issueCsrfToken(req, res, next) {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('csrf_token', token, {
    httpOnly: false, // ⚠️ A propósito: JS del cliente SÍ debe poder leer esta cookie
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.locals.csrfToken = token;
  next();
}

function verifyCsrfToken(req, res, next) {
  const cookieToken = req.cookies['csrf_token'];
  const headerToken = req.headers['x-csrf-token'];

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ error: 'Token CSRF inválido o ausente.' });
  }
  next();
}

module.exports = { issueCsrfToken, verifyCsrfToken };