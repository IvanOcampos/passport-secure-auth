// Script de un solo uso para crear/promover un usuario administrador.
// NUNCA se expone como endpoint HTTP -- se corre a mano, desde la terminal
// del servidor, por alguien con acceso directo a la infraestructura.
// Esto es a propósito: la creación de admins no debe depender de la app.

require('dotenv').config();
const mongoose = require('mongoose');
const User = require('../models/User');
const { hashPassword } = require('../services/auth.service');

async function seedAdmin() {
  const email = process.argv[2];
  const password = process.argv[3];

  if (!email || !password) {
    console.error('Uso: node src/scripts/seedAdmin.js <email> <password>');
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGO_URI);

  let user = await User.findOne({ email });

  if (user) {
    // Ya existe -> lo promovemos
    user.role = 'admin';
    await user.save();
    console.log(`Usuario existente promovido a admin: ${email}`);
  } else {
    // No existe -> lo creamos directo como admin
    const passwordHash = await hashPassword(password);
    user = await User.create({ email, passwordHash, role: 'admin' });
    console.log(`Usuario admin creado: ${email}`);
  }

  await mongoose.disconnect();
  process.exit(0);
}

seedAdmin().catch((err) => {
  console.error('Error al crear el admin:', err);
  process.exit(1);
});