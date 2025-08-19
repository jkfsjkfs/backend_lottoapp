# Patch de autenticación para backend_lottoapp

Este patch agrega **login** contra la tabla `usuario` (MySQL).

## 1) Instala dependencias
```bash
npm i express cors helmet express-rate-limit dotenv mysql2 bcryptjs
```

## 2) Variables de entorno (.env)
Agrega (o actualiza) en tu `.env`:
```
PORT=4000
DB_HOST=localhost
DB_USER=root
DB_PASS=tu_password
DB_NAME=lotto_db
DB_PORT=3306
PLAIN_ALLOWED=true
```

> Cuando migres a contraseñas con bcrypt, cambia `PLAIN_ALLOWED=false`.

## 3) Copia estos archivos al repo `backend_lottoapp`
- `src/db.js`
- `src/utils/password.js`
- `src/routes/auth.routes.js`

Mantén las carpetas `src/` existentes; si no las tienes, créalas.

## 4) Modifica tu `src/server.js` (o el archivo donde montas Express)
Añade:
```js
import authRoutes from './routes/auth.routes.js';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import 'dotenv/config';

// antes de las rutas:
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// rate limit para auth
app.use('/api/auth', rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 100,
}));

// rutas
app.use('/api/auth', authRoutes);
```

Si tu proyecto usa `require`, cambia los imports a `const ... = require('...')` o agrega `"type": "module"` en `package.json`.

## 5) Prueba
```bash
npm run start
# o npm run dev

# En otra terminal:
curl -X POST http://localhost:4000/api/auth/login   -H "Content-Type: application/json"   -d '{ "login": "juan", "password": "1234" }'
```

Respuesta esperada (200):
```json
{ "idusuario": 12, "idperfil": 2, "nombre": "Juan Pérez", "login": "juan" }
```

Si recibes 401, revisa:
- usuario existe y `activo`=1 (BIT(1))
- password coincide (en claro o bcrypt según config)
- DB_* del .env correctos

## 6) (Opcional) Índice en `usuario.login`
Recomendado para acelerar login:
```sql
CREATE INDEX idx_usuario_login ON usuario(login);
```
