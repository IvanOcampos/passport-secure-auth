# PassPort Inc. — Maestro de la Autenticación Segura

Sistema de autenticación completo: registro, sesiones con cookies, JWT con
refresh tokens, RBAC, y endurecimiento contra XSS/CSRF/fuerza bruta.

## Estado

- [x] Fase 1 — Registro y hashing con Bcrypt (cost factor 12)
- [x] Fase 2 — Sesiones persistentes con cookies (HttpOnly, Secure, SameSite)
- [x] Fase 3 — JWT stateless (access token 15m + refresh token 7d, rotación y revocación)
- [x] Fase 4 — RBAC (roles `user` / `admin`)
- [x] Fase 5 — Rate limiting, bloqueo de cuenta, CSRF (double submit cookie), sanitización XSS, Helmet
- [ ] Opcional — Recuperación de contraseña por email (no implementado, se puede agregar)

## Setup

```bash
npm install
cp .env.example .env
# Generar 3 secrets distintos:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Completar SESSION_SECRET, JWT_SECRET, JWT_REFRESH_SECRET y MONGO_URI en .env
npm run dev
```

## Endpoints

### Auth (`/api/auth`)
| Método | Ruta | Descripción |
|---|---|---|
| GET | `/csrf-token` | Emite token CSRF (llamar antes de operaciones sensibles) |
| POST | `/register` | `{ email, password }` — crea usuario |
| POST | `/login` | `{ email, password, authMode: 'session'\|'jwt' }` |
| POST | `/logout/session` | Cierra sesión (modo cookie) — requiere sesión activa |
| POST | `/logout/jwt` | Revoca el refresh token (modo JWT) |
| POST | `/refresh-token` | Rota el refresh token y devuelve un access token nuevo |

### Usuarios (`/api/users`)
| Método | Ruta | Rol requerido |
|---|---|---|
| GET | `/me` | Cualquier usuario autenticado |
| GET | `/` | Admin — lista todos los usuarios |
| GET | `/admin/security-logs` | Admin — usuarios con intentos fallidos |
| DELETE | `/:id` | Admin — requiere header `X-CSRF-Token` |

## Decisiones de seguridad clave

- **Passwords**: bcrypt, 12 salt rounds. Nunca se guarda ni se loguea texto plano.
- **Sesiones**: `express-session` + `connect-mongo`. Cookie `HttpOnly`, `Secure` (en prod), `SameSite=lax`. `regenerate()` en cada login para prevenir Session Fixation.
- **JWT**: payload mínimo (`sub`, `role`) — nunca PII, porque el payload no está cifrado, solo firmado. Refresh token guardado como **hash** en DB (permite revocación real) y rotado en cada uso.
- **RBAC**: middleware `requireRole` desacoplado de `requireAuth`, aplicable a sesión o JWT indistintamente.
- **Fuerza bruta**: doble capa — `express-rate-limit` por IP + bloqueo temporal por cuenta (`failedLoginAttempts` / `lockUntil`).
- **CSRF**: patrón *double submit cookie* (`csrf_token` cookie no-httpOnly + header `X-CSRF-Token`), aplicado a rutas de sesión que cambian estado.
- **XSS**: sanitización de todo `req.body` con la librería `xss` antes de llegar a cualquier controller; `Helmet` agrega cabeceras defensivas adicionales.
- **Enumeración de usuarios**: mensajes de error genéricos en login, independientemente de si falló el email o la contraseña.

## Pendiente si se quiere extender

- Flujo de recuperación de contraseña por email (requisito opcional del enunciado).
- Tests automatizados (requisito opcional).
- Redis como store de sesiones en vez de MongoStore, para producción a mayor escala.
