const User = require('../models/User');
const { hashPassword } = require('../services/auth.service');

async function register(req, res){
    try{
        const { email, password } = req.body;

        // Validacion
        if (!email || !password || password.length < 8){
            return res.status(400).json({ error: 'Datos inválidos'});           
        }

        // Verificamos si el usuario ya existe ANTES de hashear (evita trabajo innecesario)
        const existing = await User.findOne({ email });
        if (existing){
            return res.status(409).json({ error: 'El usuario ya existe.'});
        }

        const passwordHash = await hashPassword(password);
        const newUser = await User.create({ email, passwordHash})

        // Esto no retorna el passwordHash porque ya hicimos una condicion para filtrar en un toJSON
        return res.status(201).json({ message: 'Usuario creado.', user: newUser });
    } catch(err){
        console.error(err);
        return res.status(500).json({error: 'Error interno del servidor.'});
    }
}

module.exports = { register }