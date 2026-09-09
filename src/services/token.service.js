const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const ACCESS_EXPIRES_IN = '15m';
const REFRESH_EXPIRES_IN = '7d';

function signAccessToken(user){
    // Payload
    return jwt.sign(
        { sub: user._id.toString(), role: user.role},
        process.env.JWT_SECRET,
        { expiresIn: ACCESS_EXPIRES_IN, algorithm: 'HS256'}
    );
}

function signRefreshToken(user){
    return jwt.sign(
        { sub: user._id.toString() },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: REFRESH_EXPIRES_IN, algorithm: 'HS256' }
    );
}

function verifyAccessToken(token){
    // Forzamos el algoritmo explicitamente, no dejamos que adivine para evitar ataques tipo "alg: none"
    return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}

function verifyRefreshToken(token) {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET, { algorithms: ['HS256'] });
}

// HASH del refresh token
function hashToken(token){
    return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { signAccessToken, signRefreshToken, verifyAccessToken, verifyRefreshToken, hashToken };