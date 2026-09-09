const { verifyRefreshToken, signRefreshToken } = require('../../../../../Nueva carpeta/passport-inc/src/services/token.service');
const User = require('../models/User');
const { hashPassword, comparePassword } = require('../services/auth.service');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000;

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

        if (user.isLocked()) {
            const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(423).json({ error: `Cuenta bloqueada temporalmente. Intenta en ${minutesLeft} min.` });
        }

        const isValid = await comparePassword(password, user.passwordHash);
        if (!isValid) {
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
                user.lockUntil = new Date(Date.now() + LOCK_TIME_MS);
                user.failedLoginAttempts = 0;
            }
            await user.save();
            return genericError();
        }

        if (authMode === 'jwt'){
            const accessToken = signAccessToken(user);
            const refreshToken = signRefreshToken(user);

            // Guardamos el hash del refresh token
            user.refreshTokenHash = hashToken(refreshToken);
            await user.save();

            res.cookie('resfresh_token', resfreshToken, {
                httpOnly: true,
                secure: process.env_NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000
            });

            return res.status(200).json({ message: 'Login exitoso (JWT).', accessToken, user });
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

async function refreshAccessToken(req, res){
    const token = req.cookies['refresh_token'];
    if (!token) return res.status(401).json({ error: 'Refresh token ausente.' });

    const payload = verifyRefreshToken(token);
    const user = await User.findById(payload.sub);

    // Comparamos el RefreshToken contra el hash guardado
    if (!user || user.refreshTokenHash !== hashToken(token)){
        return res.status(401).json({ error: 'Refresh token inválido' });
    }

    // Creamos nuevos Tokens (Refresh solo tiene un uso)
    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    user.refreshTokenHash = hashToken(newRefreshToken);
    await user.save();

    res.cookie('refresh_token', newRefreshToken, { httpOnly: true, secure: true, sameSite: 'stict', maxAge: 7*24*60*60*1000});
    return res.status(200).json({ accessToken: newAccessToken });
}

module.exports = { register, login, logout, refreshAccessToken };