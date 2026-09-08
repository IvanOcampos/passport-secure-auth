const User = require('../models/User');
const { hashPassword, comparePassword } = require('../services/auth.service');

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

async function login(req, res){
    try{
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user){
            return res.status(401).json({ error: 'Credenciales Inválidas.'});
        }

        const isValid = await comparePassword(password, user.passwordHash);
        if(!isValid){
            return res.status(401).json({ error: 'Credendiales Inválidas.'})
        }

        // Regenerar el session_id una vez autenticado para evitar un "Session Fixation"
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: 'Error de sesión.'});

            req.session.userID = user._id;
            req.session.role = user.role;

            return res.status(200).json({ message: 'Login exitoso.', user })
        });
    } catch(err) {
        console.error(err);
        return res.status(500).json({ error: 'Error interno del servidor.' });
    }
}

function logout(req, res) {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'No se pudo cerrar la sesión.' });

        // clearCookie borra la cookie del navegador del cliente explícitamente
        res.clearCookie('connect.sid');
        return res.status(200).json({ message: 'Sesión cerrada.' });
    });
}

module.exports = { register, login, logout };