const User = require('../models/User');

async function getMe(req, res) {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
  return res.status(200).json({ user });
}

// Solo Administradores (protegido con requireRole en las rutas)
async function listUsers(req, res) {
  const users = await User.find();
  return res.status(200).json({ users });
}

async function deleteUser(req, res) {
  const { id } = req.params;
  await User.findByIdAndDelete(id);
  return res.status(200).json({ message: 'Usuario eliminado.' });
}

// Requerimiento del enunciado: el Administrador puede ver intentos
// fallidos de inicio de sesion (senal de posibles ataques de fuerza bruta).
async function securityLogs(req, res) {
  const suspicious = await User.find({ failedLoginAttempts: { $gt: 0 } })
    .select('email failedLoginAttempts lockUntil');
  return res.status(200).json({ suspicious });
}

module.exports = { getMe, listUsers, deleteUser, securityLogs };
