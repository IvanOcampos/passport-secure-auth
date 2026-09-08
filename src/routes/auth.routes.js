const express = require('express');
const router = express.Router();
const { register, login, logout } = require('../controllers/auth.controller')
const { requireAuth } = require('../middlewares/auth.middleware');

router.post('/register', register);
router.post('/login', login);
router.post('/logout', requireAuth, logout); // Solo se puede cerrar sesión si hay una activa

module.exports = router;