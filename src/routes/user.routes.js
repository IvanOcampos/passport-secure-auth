const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middlewares/auth.middleware');
const { requireRole } = require('../middlewares/rbac.middleware');
const { verifyCsrfToken } = require('../middlewares/csrf.middleware');
const { getMe, listUsers, deleteUser, securityLogs } = require('../controllers/user.controller');

// Cualquier usuario autenticado (sesion o JWT)
router.get('/me', requireAuth, getMe);

// Solo Administrador
router.get('/', requireAuth, requireRole('admin'), listUsers);
router.get('/admin/security-logs', requireAuth, requireRole('admin'), securityLogs);
router.delete('/:id', requireAuth, requireRole('admin'), verifyCsrfToken, deleteUser);

module.exports = router;