require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const MongoStore = require('connect-mongo').default;

const authRoutes = require('./routes/auth.routes');
const userRoutes = require('./routes/user.routes');
const { sanitizeBody } = require('./middlewares/sanitize.middleware')

const app = express();
app.use(express.json());
app.use(sanitizeBody);

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
app.use('/api/users', userRoutes);

app.use((req, res) => res.status(404).json({ error: 'Ruta no encontrada.' }));

module.exports = app;