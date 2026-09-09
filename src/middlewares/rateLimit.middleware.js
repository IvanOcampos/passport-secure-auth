const rateLimit = require('express-rate-limit');

// Limitamos intentos por IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,   // 15 minutos
    max: 10,                    // 10 intentos por IP
    standardHeaders: true,       // Devuelve info en los headers
    legacyHeaders: false,        // Evita enviar headers antiguos
    message: { error: 'Demasiados intentos de inicio de sesión. Intenta de nuevo más tarde.'}
});

// Limitamos el registro desde una misma IP
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1hora
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demasiados registros desde esta IP. Intenta más tarde.'}
});

module.exports = { loginLimiter, registerLimiter };