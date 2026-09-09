require('dotenv').config();
const { validateEnv } = require('./src/config/env');
validateEnv();

const app = require('./src/app');
const connectDB = require('./src/config/db');

const PORT = process.env.PORT || 3000;

connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`PassPort Inc. escuchando en el puerto ${PORT}`);
  });
});