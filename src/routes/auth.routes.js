const express = require('express');
const router = express.Router();
const { register, login, logoutSession, logoutJwt, refreshAccessToken, logout } = require('../controllers/auth.controller');
const { requireAuth } = require('../middlewares/auth.middleware');
const { loginLimiter, registerLimiter } = require('../middlewares/rateLimit.middleware');
const { issueCsrfToken } = require('../middlewares/csrf.middleware');

// El frontend llama esto primero para obtener el token CSRF antes de
// hacer requests que cambien estado (ej. antes de mostrar el form de login).
router.get('/csrf-token', issueCsrfToken, (req, res) => {
  res.json({ csrfToken: res.locals.csrfToken });
});

router.post('/register', registerLimiter, register);
router.post('/login', loginLimiter, login);
router.post('/logout/session', requireAuth, logout);
router.post('/logout/jwt', logoutJwt);
router.post('/refresh-token', refreshAccessToken);

module.exports = router;