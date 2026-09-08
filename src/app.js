const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const authRoutes = require('./routes/auth.routes');

const app = express();
app.use(express.json());

// Para que Express reconozca conexiones HTTPS reales y la flag Secure funcione.
app.set('trust proxy', 1);

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,                          // No reescribe la session si no hubo cambios
    saveUninitialized: false,               // No crea sesion hasta que haya algo para guardar(evita sesiones vacias)
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        ttl: 60 * 60 * 24 * 7               // Expira en el store a los 7 días
    }),
    cookie:{
        httpOnly: true,                     // JS no puede leer esta cookie
        secure: process.env.NODE_ENV === 'production', // Solo viaja por HTTPS en prod
        sameSite: 'lax',                    // Bloquea el envío automático en requests cross.site
        maxAge: 1000 * 60 * 60 * 24 * 7     // 7 días en milisegundos
    }
}));

app.use('/api/auth', authRoutes);

module.exports = app;