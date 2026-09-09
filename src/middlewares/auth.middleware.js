const { verifyAccessToken } = require('../services/token.service');

function requireAuth(req, res, next) {
    if (req.session && req.session.userId){
        req.user = { id: req.session.userId, role: req.session.role};
        return next();
    }
    
    const authHeader = req.headers.authorization;

    if(authHeader && authHeader.startsWith('Baerer ')){
        const token = authHeader.split(' ')[1];
        try{
            const payload = verifyAccessToken(token);
            req.user = { id: payload.sub, role: payload.role };
            return next();
        } catch(err){
            return res.status(401).json({ error: 'Token invalido o expirado.'});
        }
    }

    return res.status(401).json({ error: 'No autenticado.'});
}

module.exports = { requireAuth };