const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    passwordHash: {
        type: String,
        required: true
    },
    role:{
        type: String,
        enum: ['user', 'admin'],
        default: 'user'
    },
    // --- Anti fuerza bruta (bloqueo por cuenta) ---
    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
    // --- Permite revocar refresh tokens (logout real en modo JWT) ---
    refreshTokenHash: { type: String, default: null }
}, {timestamps: true});

// Evitar que el passwordhash se publique en el caso de que alguien quiera un json del mongo
userSchema.set('toJSON', {
    transform: (doc, ret) => {
        delete ret.passwordHash;
        delete ret.refreshTokenHash;
        delete ret.__v;
        return ret;
    }
});

userSchema.methods.isLocked = function () {
  return this.lockUntil && this.lockUntil > Date.now();
};

module.exports = mongoose.model('User', userSchema);