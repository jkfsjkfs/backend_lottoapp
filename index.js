// Seguridad y utilidades
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const basicAuth = require('express-basic-auth');
// const jwt = require('jsonwebtoken');

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');

// Swagger
const swaggerUi = require('swagger-ui-express');
const swaggerJSDoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3001;
const isProd = process.env.NODE_ENV === 'production';

app.use(express.json());

// CORS
app.use(cors());
/* 
if (isProd) {
  const allowed = new Set([process.env.FRONTEND_ORIGIN].filter(Boolean));
  app.use(cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);              // Postman/cURL
      if (allowed.has(origin)) return cb(null, true);  // Frontend permitido
      return cb(new Error('Origen no permitido por CORS'));
    },
    credentials: false
  }));
} else {
  // Dev: más permisivo para Expo/localhost
  app.use(cors());
}
*/

// Helmet (desactiva CSP para Swagger UI si estuviera activo)
app.use(helmet({ contentSecurityPolicy: false }));

// Solo confía en 1 proxy en prod (nginx/traefik). En dev: no confíes.
app.set('trust proxy', isProd ? 1 : false);

// Rate limiting: usa la misma política explícitamente
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  trustProxy: isProd ? 1 : false,  // 👈 clave
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(['/api', '/auth'], apiLimiter);

// === SOLO LOCALHOST para Swagger (en desarrollo) ===
function allowLocalOnly(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || '';
  const localIps = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
  if (localIps.has(ip)) return next();

  const xff = (req.headers['x-forwarded-for'] || '').toString().split(',')[0]?.trim();
  if (localIps.has(xff)) return next();

  return res.status(403).send('Forbidden: Available only on server');
}

// Config DB
const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, // OJO: tu .env usa DB_PASSWORD
  database: process.env.DB_NAME,
  // ssl: { rejectUnauthorized: true }, // ← descomenta si tu proveedor de DB lo requiere
};

// Pool para mejor performance
const pool = mysql.createPool({
  ...dbConfig,
  waitForConnections: true,
  connectionLimit: 10,
  enableKeepAlive: true,
});

// Helpers
function bitToBool(val) {
  if (val === null || val === undefined) return false;
  if (Buffer.isBuffer(val)) return val[0] === 1;
  if (typeof val === 'number') return val === 1;
  if (typeof val === 'boolean') return val;
  return String(val) === '1';
}

let bcrypt;
try { bcrypt = require('bcryptjs'); } catch { bcrypt = null; }
const allowPlain = String(process.env.PLAIN_ALLOWED || '').toLowerCase() === 'true';

async function verifyPassword(inputPassword, stored) {
  
  // 1) bcrypt si hay hash
  if (bcrypt && stored && typeof stored === 'string' && stored.startsWith('$2')) {
    try {
      return await bcrypt.compare(inputPassword, stored);
    } catch { /* ignore */ }
  }
  
  // 2) fallback en claro si está habilitado
  if (allowPlain) return inputPassword === stored;
  
  return false;
}

// Swagger Spec (solo se construye si NO estás en producción)
let swaggerSpec;


  const baseUrl = process.env.PUBLIC_BASE_URL || `http://localhost:${port}`;
  swaggerSpec = swaggerJSDoc({
    definition: {
      openapi: '3.0.0',
      info: {
        title: 'Lotto API',
        version: '1.0.0',
        description: 'API para gestionar registros de la rifa/lotto',
      },
      servers: [{ url: baseUrl, description: 'Server' }],
      components: {
        securitySchemes: {
          // 👇 Solo apiKey por header
          appKeyHeader: { type: 'apiKey', in: 'header', name: 'x-app-key' },
        },
      },
      // 👇 Seguridad global: solo x-app-key en /api/* (no para /auth)
      security: [{ appKeyHeader: [] }],
    },
    apis: ['./index.js'],
  });

  // Proteger /docs (solo accesible desde localhost en dev)
  const docsAuth = basicAuth({
    users: { [process.env.DOCS_USER || 'admin']: process.env.DOCS_PASS || 'changeme' },
    challenge: true,
  });

  app.use(
    '/docs',
    allowLocalOnly,   // solo localhost
    docsAuth,         // basic auth adicional
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec)
  );


// Home
app.get('/', (req, res) => {
  if (!isProd) {
    return allowLocalOnly(req, res, () => res.redirect('/docs'));
  }
  res.send('Lotto API');
});




// Middleware x-app-key (opcional) — solo para /api/*
function appKeyGuard(req, res, next) {

  const key = req.headers['x-app-key'];
  
  if (!key || key !== process.env.APP_KEY) {
    return res.status(401).json({ error: 'x-app-key inválida' });
  }
  
  next();
}






// ======= Auth (contra tabla usuario) =======
/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Autenticación de usuario 
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [login, password]
 *             properties:
 *               login: { type: string, example: "rifa" }
 *               password: { type: string, example: "123456" }
 *     responses:
 *       200:
 *         description: Usuario autenticado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 idusuario: { type: integer }
 *                 idperfil: { type: integer }
 *                 nombre: { type: string }
 *                 login: { type: string }
 *       401: { description: Credenciales inválidas o usuario inactivo }
 *       400: { description: Faltan credenciales }
 */
app.post('/auth/login', appKeyGuard, async (req, res) => {
  try {
    const { login, password } = req.body || {};
    if (!login || !password) {
      return res.status(400).json({ message: 'Faltan credenciales' });
    }

    const [rows] = await pool.query(
      `SELECT idusuario, idperfil, nombre, login, password, activo, comision
         FROM usuario
        WHERE login = ?
        LIMIT 1`,
      [login]
    );

    if (!rows || rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const row = rows[0];
    if (!bitToBool(row.activo)) {
      return res.status(401).json({ message: 'Usuario inactivo' });
    }

    const ok = await verifyPassword(password, row.password || '');
    
    if (!ok) {
      return res.status(401).json({ message: 'Credenciales NO válidas' });
    }
    

    // Éxito: devolvemos perfil mínimo para frontend
    return res.json({
      idusuario: row.idusuario,
      idperfil: row.idperfil,
      nombre: row.nombre,
      login: row.login,
    });
    
  } catch (err) {
    console.error('auth/login error', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

// ======= Rutas API =======

/**
 * @openapi
 * /api/loterias:
 *   get:
 *     summary: Lista de loterías activas
 *     tags: [Loterias]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de loterías
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   idloteria: { type: integer }
 *                   nombre: { type: string }
 *       401: { description: No autorizado }
 *       500: { description: Error en el servidor }
 */
app.get('/api/loterias', appKeyGuard, async (req, res) => {
  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.execute(
        'SELECT idloteria, descrip FROM loteria WHERE activa'
      );
      res.json(rows);
    } finally {
      conn.release();
    }
  } catch (error) {
    console.error('Error al consultar loterías:', error);
    res.status(500).json({ error: 'Error al obtener las loterías' });
  }
});

/**
 * @openapi
 * /api/apuestas:
 *   post:
 *     summary: Registra una apuesta con cabecera y detalles
 *     tags: [Apuestas]
 *     security: [ { appKeyHeader: [] } ]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [idusuario, nombre, telefono, loterias, apuestas]
 *             properties:
 *               idusuario: { type: integer, example: 5 }
 *               nombre: { type: string, example: "Carlos Pérez" }
 *               telefono: { type: string, example: "3001234567" }
 *               loterias:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     idloteria: { type: integer }
 *                     descrip: { type: string }
 *               apuestas:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     numero: { type: string }
 *                     valor: { type: number }
 *     responses:
 *       200: { description: Apuesta registrada con éxito }
 *       400: { description: Datos incompletos }
 *       500: { description: Error en el servidor }
 */
app.post('/api/apuestas', appKeyGuard, async (req, res) => {
  const { idusuario, nombre, telefono, loterias, apuestas } = req.body;

  if (!idusuario || !nombre || !telefono || !Array.isArray(loterias) || !Array.isArray(apuestas)) {
    return res.status(400).json({ error: 'Datos incompletos' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1) Insertar cabecera
    const [result] = await conn.execute(
      'INSERT INTO registro (idusuario, nombre, telefono) VALUES (?, ?, ?)',
      [idusuario, nombre, telefono]
    );
    const idregistro = result.insertId;

    // 2) Insertar detalles (cruce apuestas × loterías)
    for (const ap of apuestas) {
      for (const lot of loterias) {
        await conn.execute(
          'INSERT INTO detalle (idregistro, numero, idloteria, valor) VALUES (?, ?, ?, ?)',
          [idregistro, ap.numero, lot.idloteria, ap.valor]
        );
      }
    }

    await conn.commit();
    res.status(200).json({ message: 'Apuesta registrada correctamente', idregistro });
  } catch (error) {
    await conn.rollback();
    console.error('Error al registrar apuesta:', error);
    res.status(500).json({ error: 'Error al registrar apuesta' });
  } finally {
    conn.release();
  }
});

/**
 * @openapi
 * /api/ventas/resumen:
 *   get:
 *     summary: Obtiene resumen de ventas del usuario para una fecha
 *     tags: [Ventas]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: idusuario
 *         required: true
 *         schema: { type: integer }
 *         description: ID del usuario logueado
 *       - in: query
 *         name: fecha
 *         required: true
 *         schema: { type: string, format: date }
 *         description: Fecha en formato YYYY-MM-DD
 *     responses:
 *       200:
 *         description: Resumen de ventas y comisiones
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ventasTotales: { type: number }
 *                 comisiones: { type: number }
 */
app.get('/api/ventas/resumen', appKeyGuard, async (req, res) => {
  const { idusuario, fecha } = req.query;
  if (!idusuario || !fecha) {
    return res.status(400).json({ error: 'Faltan parámetros idusuario o fecha' });
  }

  try {
    const conn = await pool.getConnection();
    try {
      // Traer comision del usuario
      const [userRows] = await conn.execute(
        'SELECT comision FROM usuario WHERE idusuario = ?',
        [idusuario]
      );
      if (userRows.length === 0) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      const porcentaje = userRows[0].comision || 0;

      // Sumar todas las apuestas del día para el usuario
      const [rows] = await conn.execute(
        `SELECT SUM(d.valor) as total
           FROM registro r
           JOIN detalle d ON r.id = d.idregistro
          WHERE r.idusuario = ? 
            AND DATE(r.fecha) = ?`,
        [idusuario, fecha]
      );

      const ventasTotales = rows[0].total || 0;
      const comisiones = ventasTotales * (porcentaje / 100);

      res.json({ ventasTotales, comisiones });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Error en /api/ventas/resumen:', err);
    res.status(500).json({ error: 'Error interno' });
  }
});

/**
 * @openapi
 * /api/ventas/ultima:
 *   get:
 *     summary: Última venta del usuario
 *     tags: [Ventas]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: idusuario
 *         required: true
 *         schema: { type: integer }
 *     responses:
 *       200:
 *         description: Última venta con sus detalles
 */
app.get('/api/ventas/ultima', appKeyGuard, async (req, res) => {
  const { idusuario } = req.query;
  if (!idusuario) return res.status(400).json({ error: 'Falta idusuario' });

  try {
    const conn = await pool.getConnection();
    try {
      // Trae el registro más reciente
      const [registros] = await conn.execute(
        `SELECT * FROM registro WHERE idusuario = ? ORDER BY fecha DESC LIMIT 1`,
        [idusuario]
      );

      if (registros.length === 0) return res.json(null);

      const registro = registros[0];

      // Trae los detalles asociados
      const [detalles] = await conn.execute(
        `SELECT d.numero, d.valor, l.descrip as loteria
           FROM detalle d
           JOIN loteria l ON l.idloteria = d.idloteria
          WHERE d.idregistro = ?`,
        [registro.id]
      );

      res.json({
        registro,
        detalles,
      });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error('Error al consultar última venta:', err);
    res.status(500).json({ error: 'Error al consultar última venta' });
  }
});

/**
 * @openapi
 * /api/reportes/ventas:
 *   get:
 *     summary: Ventas detalladas en un rango de fechas (opcional por usuario)
 *     tags: [Reportes]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
  *       - in: query
 *         name: idusuario
 *         required: false
 *         schema: { type: integer, example: 5 }
 *         description: Si se envía, filtra las ventas de un usuario específico* 
 *       - in: query
 *         name: desde
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-01" }
 *       - in: query
 *         name: hasta
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-18" }
 *     responses:
 *       200:
 *         description: Lista de ventas
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id: { type: integer }
 *                   idusuario: { type: integer }
 *                   nombre: { type: string }
 *                   telefono: { type: string }
 *                   fecha: { type: string, format: date-time }
 *                   numero: { type: string }
 *                   valor: { type: number }
 *                   loteria: { type: string }
 */
app.get('/api/reportes/ventas', appKeyGuard, async (req, res) => {
  const { idusuario, desde, hasta } = req.query;
  if (!desde || !hasta) {
    return res.status(400).json({ error: 'Faltan fechas' });
  }
  try {
    let sql = `
      SELECT r.id, r.idusuario, r.nombre, r.telefono, r.fecha, 
             d.numero, d.valor, l.descrip as loteria
      FROM registro r
      JOIN detalle d ON d.idregistro = r.id
      JOIN loteria l ON l.idloteria = d.idloteria
      WHERE DATE(r.fecha) BETWEEN ? AND ?
    `;
    const params = [desde, hasta];

    if (idusuario) {
      sql += " AND r.idusuario = ?";
      params.push(idusuario);
    }

    sql += " ORDER BY r.fecha DESC";

    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error consultando ventas' });
  }
});


/**
 * @openapi
 * /api/reportes/premios:
 *   get:
 *     summary: Premios (ganadores) por fecha
 *     tags: [Reportes]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: fecha
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-18" }
 *     responses:
 *       200:
 *         description: Lista de premios por fecha
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   numero: { type: string }
 *                   valor: { type: number }
 *                   nombre: { type: string }
 *                   telefono: { type: string }
 *                   loteria: { type: string }
 */
app.get('/api/reportes/premios', appKeyGuard, async (req, res) => {
  const { fecha } = req.query;
  if (!fecha) return res.status(400).json({ error: 'Falta la fecha' });

  try {
    const [rows] = await pool.query(
      `SELECT d.numero, d.valor, r.nombre, r.telefono, l.descrip as loteria
       FROM detalle d
       JOIN registro r ON r.id = d.idregistro
       JOIN loteria l ON l.idloteria = d.idloteria
       WHERE DATE(r.fecha) = ? 
         AND d.numero IN (
           SELECT numeroGanador FROM resultados WHERE DATE(fecha) = ?
         )`,
      [fecha, fecha]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error consultando premios' });
  }
});


/**
 * @openapi
 * /api/reportes/resultados:
 *   get:
 *     summary: Resultados de loterías por fecha
 *     tags: [Reportes]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: fecha
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-18" }
 *     responses:
 *       200:
 *         description: Resultados de loterías
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   loteria: { type: string }
 *                   numeroGanador: { type: string }
 *                   serie: { type: string }
 *                   fecha: { type: string, format: date-time }
 */
app.get('/api/reportes/resultados', appKeyGuard, async (req, res) => {
  const { fecha } = req.query;
  if (!fecha) return res.status(400).json({ error: 'Falta la fecha' });

  try {
    const [rows] = await pool.query(
      `SELECT l.descrip as loteria, r.numeroGanador, r.serie, r.fecha
       FROM resultados r
       JOIN loteria l ON l.idloteria = r.idloteria
       WHERE DATE(r.fecha) = ?`,
      [fecha]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error consultando resultados' });
  }
});


/**
 * @openapi
 * /api/reportes/cierres:
 *   get:
 *     summary: Horarios de cierre de las loterías
 *     tags: [Reportes]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de cierres
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   idloteria: { type: integer }
 *                   descrip: { type: string }
 *                   hora_cierre: { type: string }
 */
app.get('/api/reportes/cierres', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT idloteria, descrip, hora_cierre FROM loteria`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error consultando cierres' });
  }
});

/**
 * @openapi
 * /api/memvar:
 *   get:
 *     summary: Variables generales de configuración
 *     tags: [Configuración]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: variable
 *         required: false
 *         schema: { type: string }
 *         description: Nombre de la variable a consultar
 *     responses:
 *       200:
 *         description: Lista de variables o variable puntual
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   variable: { type: string }
 *                   valor: { type: string }
 */
app.get('/api/memvar', appKeyGuard, async (req, res) => {
  const { variable } = req.query;
  try {
    let rows;
    if (variable) {
      [rows] = await pool.query(
        `SELECT variable, valor FROM memvar WHERE variable = ?`,
        [variable]
      );
    } else {
      [rows] = await pool.query(`SELECT variable, valor FROM memvar`);
    }
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error consultando variables' });
  }
});


// Arranque
app.listen(port, () => {
  console.log(`Servidor backend en http://localhost:${port}`);
  if (!isProd) {
    console.log(`Swagger UI (solo localhost) en http://localhost:${port}/docs`);
  } else {
    console.log('Swagger deshabilitado en producción');
  }
});
