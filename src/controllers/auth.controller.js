const User = require('../models/User');
const { hashPassword, comparePassword } = require('../services/auth.service');
const { signAccessToken, signRefreshToken, verifyRefreshToken, hashToken } = require('../services/token.service');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME_MS = 15 * 60 * 1000;

async function register(req, res){
    try{
        const { email, password } = req.body;

        // Validacion
        if (!email || !password) {
            return res.status(400).json({
                error: 'El email y la contraseña son obligatorios.'
            });
        }

        // Validamos la longitud mínima de la contraseña
        if (password.length < 8) {
            return res.status(400).json({
                error: 'La contraseña debe tener al menos 8 caracteres.'
            });
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
    try {
        const { email, password, authMode } = req.body; // authMode: 'session' | 'jwt'
        const user = await User.findOne({ email });

        // Mensaje SIEMPRE generico: nunca revelamos si fallo el email o la
        // password (evita User Enumeration).
        const genericError = () => res.status(401).json({ error: 'Credenciales invalidas.' });
        if (!user) return genericError();

        // Bloqueo temporal por fuerza bruta a nivel de CUENTA (complementa el
        // rate limit por IP: cubre el caso de un atacante con IPs rotativas).
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

    user.failedLoginAttempts = 0;
    user.lockUntil = null;

    if (authMode === 'jwt') {
      const accessToken = signAccessToken(user);
      const refreshToken = signRefreshToken(user);

      user.refreshTokenHash = hashToken(refreshToken);
      await user.save();

      // El refresh token viaja SOLO en cookie httpOnly (nunca en el body
      // ni en localStorage: si viviera ahi, un XSS lo robaria directo).
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000
      });

      return res.status(200).json({
        message: 'Login exitoso (JWT).',
        accessToken, // el cliente lo guarda EN MEMORIA y lo manda como Authorization: Bearer <token>
        user
      });
    }

        // Modo sesion (default)
        await user.save();
        req.session.regenerate((err) => {
        if (err) return res.status(500).json({ error: 'Error de sesion.' });
        req.session.userId = user._id;
        req.session.role = user.role;
        return res.status(200).json({ message: 'Login exitoso (sesion).', user });
        });

    } catch (err) {
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

async function logoutJwt(req, res) {
  try {
    const token = req.cookies['refresh_token'];
    if (token) {
      const payload = verifyRefreshToken(token);
      // Invalidamos el refresh token en DB: aunque el atacante tenga una
      // copia, deja de ser utilizable desde este momento.
      await User.findByIdAndUpdate(payload.sub, { refreshTokenHash: null });
    }
    res.clearCookie('refresh_token');
    return res.status(200).json({ message: 'Sesion JWT cerrada.' });
  } catch (err) {
    res.clearCookie('refresh_token');
    return res.status(200).json({ message: 'Sesion JWT cerrada.' });
  }
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

module.exports = { register, login, logout, refreshAccessToken, logoutJwt };