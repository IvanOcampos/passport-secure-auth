function requireRole(...allowedRoles){
    return(req, res, next) =>{
        // Verificamos al usuario
        if(!req.user){
            return res.status(401).json({ error: 'No autenticado.'})
        }
        if (!allowedRoles.includes(req.user.role)){
            return res.status(403).json({ error: 'No tienes permisos para esta acción' });
        }
        next();
    };
}

module.exports = { requireRole };