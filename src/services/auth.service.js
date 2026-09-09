const bcrypt = require('bcrypt');

// Define el costo computacional del hash, con un estandar de 12 para balancear seguridad vs latencia del servidor, cada +1 DUPLICA el tiempo de cómputo.
const SALT_ROUNDS = 12;

async function hashPassword(plainPassword) {
    //bcrypt recibe la contraseña original y el costo (12), el salt se genera automáticamente
    const hash = await bcrypt.hash(plainPassword, SALT_ROUNDS);

    return hash;
}

async function comparePassword(plainPassword, storedHash){
    // compare extrae el salt del storedHash automáticamente y repite el proceso
    return bcrypt.compare(plainPassword, storedHash);
}

module.exports = {hashPassword, comparePassword};