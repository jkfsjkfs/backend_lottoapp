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
  connectionLimit: 5,
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

  if (!process.env.DOCS_USER || !process.env.DOCS_PASS) {
    throw new Error("Son obligatorias las configuraciones de protección DOCS_USER,DOCS_PASS");
  }

  const docsAuth = basicAuth({
    users: { [process.env.DOCS_USER]: process.env.DOCS_PASS },
    challenge: true,
  });

  app.use(
    '/docs',
    //allowLocalOnly,   // solo localhost
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
      ` SELECT u.idusuario, u.idperfil, u.nombre, u.login, u.password, u.activo 
        , IFNULL((
			  SELECT c.porcentaje
			  FROM comision c
			  WHERE c.idusuario = u.idusuario
				AND c.fecha <= NOW()
			  ORDER BY c.fecha DESC, c.idcomision DESC
			  LIMIT 1
			),0) AS comision
         FROM usuario u 
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
      comision: row.comision
    });
    
  } catch (err) {
    console.error('auth/login error', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

// ======= Rutas API =======

/**
 * @openapi
 * /api/loteriasdia:
 *   get:
 *     summary: Lista de loterías
 *     tags: [Loterias]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: series
 *         required: false
 *         schema: 
 *           type: integer
 *           enum: [0, 1]
 *         description: 
 *           0 = solo sin series,
 *           1 = solo con series,
 *           vacío o nulo = todas
 *     responses:
 *       200:
 *         description: Lista de loterías disponibles
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   idloteria: { type: integer }
 *                   codigo: { type: string }
 *                   descrip: { type: string }
 *                   dia: { type: integer }
 *                   hora_ini: { type: string, format: time }
 *                   hora_fin: { type: string, format: time }
 *       401: { description: No autorizado }
 *       500: { description: Error en el servidor }
 */
app.get('/api/loteriasdia', appKeyGuard, async (req, res) => {
  const { series } = req.query;

  let cSql = '';
  if(series)
    cSql = ` AND l.serie = ${series} `
  

  try {
    const conn = await pool.getConnection();
    try {
      const [rows] = await conn.query(`
        SELECT 
            l.idloteria,
            l.codigo,
            l.descrip,
            l.activa, l.serie, 
            c.dia,
            c.hora_ini,
            c.hora_fin
        FROM loteria l
        JOIN cierre c 
            ON l.idloteria = c.idloteria
           AND c.dia = DAYOFWEEK(NOW())
           AND CAST(NOW() AS TIME) BETWEEN c.hora_ini AND c.hora_fin
        WHERE l.activa = 1  AND c.activo = 1
        ${cSql}
        ORDER BY c.hora_fin , l.codigo
      `);

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
 * /api/series:
 *   get:
 *     summary: Lista de series activas
 *     tags: [Series]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de series
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   idserie: { type: integer }
 *                   descrip: { type: string }
 */
app.get('/api/series', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT idserie, descrip 
         FROM serie 
        ORDER BY descrip`
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar series:', err);
    res.status(500).json({ error: 'Error al obtener series' });
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
 *                     numero: { type: string, example: "9999" }
 *                     valor: { type: number, example:  0 }
 *                     idserie: { type: number, example:  0 }
 *                     valorCombinado: { type: number, example:  0 }
 *     responses:
 *       200: { description: Apuesta registrada con éxito }
 *       400: { description: Datos incompletos }
 *       500: { description: Error en el servidor }
 */
app.post('/api/apuestas', appKeyGuard, async (req, res) => {
  const { idusuario, nombre, telefono, loterias, apuestas } = req.body;

  if (!idusuario || !Array.isArray(loterias) || !Array.isArray(apuestas)) {
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

        const [detresult] =await conn.execute(
          'INSERT INTO detalle (idregistro, numero, idloteria, valor) VALUES (?, ?, ?, ?)',
          [idregistro, ap.numero, lot.idloteria, ap.valor]
        );
        const detregistro = detresult.insertId;
        
        if(ap.idserie > 0){
          await conn.execute(
            'INSERT INTO detserie (iddetalle, idserie) VALUES (?, ?)',
            [detregistro, ap.idserie]
          );
        }
        else if(ap.valorCombinado > 0)
        {
          await conn.execute(
            'INSERT INTO combinado (iddetalle, valor) VALUES (?, ?)',
            [detregistro, ap.valorCombinado]
          );
        }
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
 *         required: false
 *         schema: { type: integer }
 *         description: ID del usuario logueado
 *       - in: query
 *         name: fecha
 *         required: true
 *         schema: { type: string, format: date }
 *         description: Fecha en formato YYYY-MM-DD
  *       - in: query
 *         name: idpromotor
 *         required: false
 *         schema: { type: integer }
 *         description: ID del promotor
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
 *                 cantidad: { type: integer }
 */
app.get('/api/ventas/resumen', appKeyGuard, async (req, res) => {
  const { idusuario, fecha, idpromotor } = req.query;
  if (!fecha) {
    return res.status(400).json({ error: 'Faltan parámetros de fecha' });
  }

  try {
    const conn = await pool.getConnection();
    try {

      let sql = `
      SELECT 
          SUM(d.valor) AS total,
          COUNT(DISTINCT r.id) AS cantidad,
          SUM(
            d.valor * (
              SELECT c.porcentaje / 100.0
              FROM comision c
              WHERE c.idusuario = r.idusuario
                AND c.fecha <= ?
              ORDER BY c.fecha DESC, c.idcomision DESC
              LIMIT 1
            )
          ) AS comisiones
        FROM registro r
        JOIN detalle d ON r.id = d.idregistro
        WHERE DATE(r.fecha) = ? `;
    
        const params = [fecha, fecha];

      if (idpromotor) {
        sql += ` AND r.idusuario IN 
            (SELECT idvendedor 
              FROM vendedores 
              WHERE idpromotor = ?)  
            ) `;
          params.push(idpromotor);
      }
      else if (idusuario) {
        sql += ` AND r.idusuario = ?`;
        params.push(idusuario);
      }



      const [rows] = await pool.query(sql, params);


      const porcentaje = rows[0]?.porcentaje || 0;
      const ventasTotales = rows[0]?.total || 0;
      const comisiones = rows[0]?.comisiones || 0;
      const cantidad = rows[0]?.cantidad || 0;

      res.json({ ventasTotales, comisiones, cantidad });
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
 *     summary: Ventas detalladas en un rango de fechas (agrupadas por registro)
 *     tags: [Reportes]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: idusuario
 *         required: false
 *         schema: { type: integer, example: 1031 }
 *         description: Si se envía, filtra las ventas de un usuario específico.
 *       - in: query
 *         name: desde
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-01" }
 *         description: Fecha inicial del rango (YYYY-MM-DD).
 *       - in: query
 *         name: hasta
 *         required: true
 *         schema: { type: string, format: date, example: "2025-08-20" }
 *         description: Fecha final del rango (YYYY-MM-DD).
 *     responses:
 *       200:
 *         description: Lista de ventas agrupadas por registro
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id: { type: integer, example: 49 }
 *                   idusuario: { type: integer, example: 1031 }
 *                   nombre: { type: string, example: "JuanC" }
 *                   telefono: { type: string, example: "3165218367" }
 *                   fecha: { type: string, format: date-time, example: "2025-08-20T19:50:43.000Z" }
 *                   detalles:
 *                     type: array
 *                     items:
 *                       type: object
 *                       properties:
 *                         numero: { type: string, example: "2258" }
 *                         valor: { type: number, example: 2000 }
 *                         loteria: { type: string, example: "Medellin" }
 *       400:
 *         description: Faltan fechas en la consulta
 *       500:
 *         description: Error consultando ventas
 */
app.get('/api/reportes/ventas', appKeyGuard, async (req, res) => {
  const { idusuario, desde, hasta } = req.query;
  if (!desde || !hasta) {
    return res.status(400).json({ error: 'Faltan fechas' });
  }

  try {
    let sql = `
      SELECT r.id, r.idusuario, r.nombre, r.telefono, r.fecha,
             d.numero, d.valor, l.descrip as loteria, 
             IFNULL(v.idpromotor,0) AS idpromotor, 
             IFNULL(s.descrip,'') AS serie, 
             IFNULL(c.valor,0) as combinado
      FROM registro r
      JOIN detalle d ON d.idregistro = r.id
      JOIN loteria l ON l.idloteria = d.idloteria
        LEFT JOIN detserie ds ON d.iddetalle = ds.iddetalle 
		    LEFT JOIN serie s ON ds.idserie = s.idserie 
		    LEFT JOIN combinado c ON d.iddetalle = c.iddetalle 
        LEFT JOIN vendedores v ON r.idusuario = v.idvendedor        
      WHERE DATE(r.fecha) BETWEEN ? AND ?
    `;
    const params = [desde, hasta];

    if (idusuario) {
      sql += " AND r.idusuario = ?";
      params.push(idusuario);
    }

    sql += " ORDER BY r.fecha DESC";

    const [rows] = await pool.query(sql, params);

    // Agrupar en Node
    const registros = {};
    rows.forEach(r => {
      if (!registros[r.id]) {
        registros[r.id] = {
          id: r.id,
          idusuario: r.idusuario,
          nombre: r.nombre,
          telefono: r.telefono,
          fecha: r.fecha,
          idpromotor: r.idpromotor,
          detalles: []
        };
      }
      registros[r.id].detalles.push({
        numero: r.numero,
        valor: r.valor,
        loteria: r.loteria,
        serie: r.serie,
        combinado: r.combinado
      });
    });

    res.json(Object.values(registros));
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

      // 1) Invocar internamente sync-resultados
      await axios.post(`http://localhost:${port}/api/admin/sync-resultados/${fecha}`, {}, {
        headers: { 'x-app-key': process.env.APP_KEY } // 👈 obligatorio porque protegiste con appKeyGuard
      });


    const [rows] = await pool.query(
      `SELECT p.*, l.descrip as loteria, l.codigo, u.nombre as vendedor
        FROM premios p 
        JOIN loteria l ON p.idloteria = l.idloteria
        JOIN usuario u ON p.idusuario = u.idusuario
      WHERE DATE(p.fecha_registro) = ?;`,
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
    // 1) Invocar internamente sync-resultados
    await axios.post(`http://localhost:${port}/api/admin/sync-resultados/${fecha}`, {}, {
      headers: { 'x-app-key': process.env.APP_KEY } // 👈 obligatorio porque protegiste con appKeyGuard
    });

    // 2) Luego consultar normalmente los resultados en BD
    const [rows] = await pool.query(
      ` SELECT l.idloteria, l.descrip as loteria, r.numero, r.idresultado, 
               r.publicado, l.codigo,
               r.fecha, IFNULL(s.idserie,0) AS idserie, 
               IFNULL(s.descrip,'') AS serie
            FROM resultado r
            JOIN loteria l ON l.idloteria = r.idloteria
            LEFT JOIN serie s ON r.serie = s.codigo
          WHERE DATE(r.fecha) =  ?`,
      [fecha]
    );

    res.json(rows);
  } catch (err) {
    console.error('Error al consultar resultados:', err);
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
      `SELECT 
            l.idloteria,
            l.codigo,
            l.descrip,
            c.dia,
            c.hora_ini,
            c.hora_fin
        FROM loteria l
        JOIN cierre c 
            ON l.idloteria = c.idloteria
           AND c.dia = DAYOFWEEK(NOW())
        WHERE l.activa = 1  AND c.activo = 1
        ORDER BY c.hora_fin , l.codigo`
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

/**
 * @openapi
 * /api/memvar/{variable}:
 *   put:
 *     summary: Actualiza el valor de una variable de configuración
 *     tags: [Configuración]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: path
 *         name: variable
 *         required: true
 *         schema: { type: string }
 *         description: Nombre de la variable (ej: apuesta_max)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               valor: { type: string, example: "10000" }
 *     responses:
 *       200: { description: Variable actualizada }
 */
app.put('/api/memvar/:variable', appKeyGuard, async (req, res) => {
  const { variable } = req.params;
  const { valor } = req.body;
  if (!valor) return res.status(400).json({ error: "Falta el valor" });

  try {
    const [result] = await pool.query(
      "UPDATE memvar SET valor = ? WHERE variable = ?",
      [valor, variable]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Variable no encontrada" });
    }

    res.json({ success: true, variable, valor });
  } catch (err) {
    
    // Si vino de un trigger (SIGNAL), MySQL manda el mensaje en err.sqlMessage
    if (err.sqlMessage) {
      return res.status(400).json({ error: err.sqlMessage });
    }

    res.status(500).json({ error: "Error al actualizar variable" });
  }
});




/**
 * @openapi
 * /api/xnumeros:
 *   get:
 *     summary: Lista de números bloqueados
 *     tags: [Restricciones]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de números bloqueados
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   numero: { type: string }
 */
app.get('/api/xnumeros', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT numero FROM xnumeros`
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar xnumeros:', err);
    res.status(500).json({ error: 'Error al obtener los números bloqueados' });
  }
});

/**
 * @openapi
 * /api/xcifras:
 *   get:
 *     summary: Lista de cifras bloqueadas por lotería
 *     tags: [Restricciones]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de cifras bloqueadas
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   idloteria: { type: integer }
 *                   cifras: { type: string }
 */
app.get('/api/xcifras', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT idloteria, cifras FROM xcifras`
    );
    res.json(rows);
  } catch (err) {
    console.error('Error al consultar xcifras:', err);
    res.status(500).json({ error: 'Error al obtener las cifras bloqueadas' });
  }
});


// 🗑️ Eliminar una venta
/**
 * @openapi
 * /api/ventas/{id}:
 *   delete:
 *     summary: Elimina una venta por ID
 *     tags:
 *       - Ventas
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: ID de la venta a eliminar
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Venta eliminada correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 message:
 *                   type: string
 *       404:
 *         description: Venta no encontrada
 *       500:
 *         description: Error en el servidor
 */
app.delete("/api/ventas/:id", async (req, res) => {
  const { id } = req.params;
  try {
    // 1. Buscar la fecha del registro antes de eliminar
    const [rows] = await pool.query(
      "SELECT fecha FROM registro WHERE id = ?",
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: "Venta no encontrada" });
    }

    const fechaRegistro = new Date(rows[0].fecha);
    const hoy = new Date();

    // normalizamos a solo fecha (sin horas)
    const fechaRegistroStr = fechaRegistro.toISOString().slice(0, 10);
    const hoyStr = hoy.toISOString().slice(0, 10);

    if (fechaRegistroStr !== hoyStr) {
      return res
        .status(400)
        .json({ error: "No se permite eliminar registros de fechas anteriores a hoy" });
    }

    // 2. Eliminar si la fecha es de hoy
    const [result] = await pool.query("DELETE FROM registro WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Venta no encontrada" });
    }

    res.json({ success: true, message: `Venta ${id} eliminada` });
  } catch (err) {
    console.error("Error eliminando venta:", err);
    res.status(500).json({ error: "Error eliminando venta" });
  }
});



/**
 * @openapi
 * /api/admin/numerosbloqueados:
 *   get:
 *     summary: Lista de números bloqueados (admin)
 *     tags: [Admin - Números Bloqueados]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Lista de números bloqueados
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   numero: { type: string, example: "1234" }
 *       401: { description: No autorizado }
 *       500: { description: Error interno }
 */
app.get('/api/admin/numerosbloqueados', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT numero FROM xnumeros`);
    res.json(rows);
  } catch (err) {
    console.error("Error al consultar números bloqueados:", err);
    res.status(500).json({ error: "Error al obtener los números bloqueados" });
  }
});

/**
 * @openapi
 * /api/admin/numerosbloqueados:
 *   post:
 *     summary: Agrega un número bloqueado
 *     tags: [Admin - Números Bloqueados]
 *     security: [ { appKeyHeader: [] } ]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [numero]
 *             properties:
 *               numero: { type: string, example: "1234" }
 *     responses:
 *       200:
 *         description: Número agregado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *       400: { description: Datos inválidos }
 *       500: { description: Error interno }
 */
app.post('/api/admin/numerosbloqueados', appKeyGuard, async (req, res) => {
  const { numero } = req.body;
  if (!numero) {
    return res.status(400).json({ error: "El campo 'numero' es obligatorio" });
  }

  try {
    const [result] = await pool.query(
      "INSERT INTO xnumeros (numero) VALUES (?)",
      [numero]
    );
    res.json({ success: true, message: `Número ${numero} agregado`, id: result.insertId });
  } catch (err) {
    console.error("Error al agregar número bloqueado:", err);
    
    if (err.sqlMessage) {
      return res.status(400).json({ error: err.sqlMessage });
    }

    res.status(500).json({ error: "Error al agregar número bloqueado" });
  }

  
  
});


/**
 * @openapi
 * /api/admin/numerosbloqueados/{numero}:
 *   delete:
 *     summary: Elimina un número bloqueado
 *     tags: [Admin - Números Bloqueados]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: path
 *         name: numero
 *         required: true
 *         schema: { type: string }
 *         description: Número a desbloquear
 *     responses:
 *       200:
 *         description: Número eliminado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 message: { type: string }
 *       404: { description: Número no encontrado }
 *       500: { description: Error en el servidor }
 */
app.delete('/api/admin/numerosbloqueados/:numero', appKeyGuard, async (req, res) => {
  const { numero } = req.params;
  try {
    const [result] = await pool.query("DELETE FROM xnumeros WHERE numero = ?", [numero]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Número no encontrado" });
    }

    res.json({ success: true, message: `Número ${numero} eliminado` });
  } catch (err) {
    console.error("Error eliminando número:", err);
    // Si vino de un trigger (SIGNAL), MySQL manda el mensaje en err.sqlMessage
    if (err.sqlMessage) {
      return res.status(400).json({ error: err.sqlMessage });
    }

    res.status(500).json({ error: "Error al eliminar número bloqueado" });
  }
});








/**
 * @openapi
 * /api/admin/loterias:
 *   get:
 *     summary: Lista todas las loterías (admin)
 *     tags: [Admin - Loterías]
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
 *                   idloteria: { type: integer, example: 1 }
 *                   codigo: { type: string, example: "MED" }
 *                   descrip: { type: string, example: "Medellín" }
 *                   activa: { type: boolean, example: true }
 *       401: { description: No autorizado }
 *       500: { description: Error interno }
 */
app.get('/api/admin/loterias', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        l.idloteria,
        l.codigo,
        l.descrip,
        l.activa,
        l.serie,
        c.dia,
        CASE c.dia
          WHEN 1 THEN 'Domingo'
          WHEN 2 THEN 'Lunes'
          WHEN 3 THEN 'Martes'
          WHEN 4 THEN 'Miércoles'
          WHEN 5 THEN 'Jueves'
          WHEN 6 THEN 'Viernes'
          WHEN 7 THEN 'Sábado'
        END AS nombre_dia,
        c.hora_ini,
        c.hora_fin,
        c.activo AS cierre_activo,
        x.cifras AS restriccion_cifras
      FROM loteria l
      LEFT JOIN cierre c ON l.idloteria = c.idloteria
      LEFT JOIN xcifras x ON l.idloteria = x.idloteria
      ORDER BY l.idloteria, c.dia
    `);

    const loterias = {};
    rows.forEach(r => {
      if (!loterias[r.idloteria]) {
        loterias[r.idloteria] = {
          idloteria: r.idloteria,
          codigo: r.codigo,
          descrip: r.descrip,
          activa: bitToBool(r.activa),
          serie: bitToBool(r.serie),
          restriccionCifras: r.restriccion_cifras || null, // 👈 campo único
          cierres: []
        };
      }

      if (r.dia !== null) {
        loterias[r.idloteria].cierres.push({
          dia: r.dia,
          nombre_dia: r.nombre_dia,
          hora_ini: r.hora_ini,
          hora_fin: r.hora_fin,
          activo: bitToBool(r.cierre_activo)
        });
      }
    });

    res.json(Object.values(loterias));
  } catch (err) {
    console.error("Error al consultar loterías:", err);
    res.status(500).json({ error: "Error al obtener las loterías" });
  }
});


/**
 * @openapi
 * /api/admin/vendedores:
 *   get:
 *     summary: Relaciones promotor-vendedor
 *     tags: [Admin - Usuarios]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: query
 *         name: idpromotor
 *         required: false
 *         schema: { type: integer }
 *         description: Si se pasa, devuelve solo los vendedores de ese promotor
 *     responses:
 *       200:
 *         description: Lista de relaciones promotor-vendedor
 */
app.get('/api/admin/vendedores', appKeyGuard, async (req, res) => {
  try {
    const { idpromotor } = req.query;

    let sql = "SELECT idpromotor, idvendedor FROM vendedores";
    let params = [];

    if (idpromotor) {
      sql += " WHERE idpromotor = ?";
      params.push(idpromotor);
    }

    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error consultando vendedores" });
  }
});




/**
 * @openapi
 * /api/admin/usuarios:
 *   get:
 *     summary: Lista todos los usuarios
 *     tags: [Admin - Usuarios]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200: { description: Lista de usuarios }
 *   post:
 *     summary: Crear usuario
 *     tags: [Admin - Usuarios]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [nombre, email, password, idperfil]
 *             properties:
 *               nombre: { type: string, example: "Juan Pérez" }
  *               password: { type: string, example: "secret123" }
 *               idperfil: { type: integer, example: 3 }
 *     responses:
 *       200: { description: Usuario creado }
 */
app.get('/api/admin/usuarios', appKeyGuard, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT idusuario, nombre, activo, idperfil, login 
       FROM usuario`
    );

    // Convertimos activo a boolean
    const usuarios = rows.map(u => ({
      ...u,
      activo: bitToBool(u.activo) // 👈 aquí usamos el helper
    }));

    res.json(usuarios);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


/**
 * @openapi
 * /api/admin/usuarios:
 *   post:
 *     summary: Crear un nuevo usuario
 *     tags: [Admin - Usuarios]
 *     security: [ { appKeyHeader: [] } ]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [nombre, login, password, idperfil]
 *             properties:
 *               nombre: { type: string, example: "Juan Pérez" }
 *               login: { type: string, example: "jperez" }
 *               password: { type: string, example: "123456" }
 *               idperfil: 
 *                 type: integer
 *                 enum: [1, 2, 3]
 *                 description: 1=Admin, 2=Promotor, 3=Vendedor
 *               activo: { type: boolean, example: true }
 *               idpromotor: 
 *                 type: integer
 *                 example: 1021
 *                 description: Solo requerido si se crea un Vendedor desde Admin
 *     responses:
 *       200:
 *         description: Usuario creado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *                 idusuario: { type: integer }
 *       400: { description: Faltan campos obligatorios }
 *       409: { description: Login ya en uso }
 *       500: { description: Error interno }
 */
app.post('/api/admin/usuarios', appKeyGuard, async (req, res) => {
  const { nombre, login, password, idperfil, activo, idpromotor } = req.body;

  if (!nombre || !login || !password || !idperfil) {
    return res.status(400).json({ error: "Faltan campos obligatorios" });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Verificar login único
    const [exists] = await conn.query(
      "SELECT idusuario FROM usuario WHERE login = ? LIMIT 1",
      [login]
    );
    if (exists.length > 0) {
      await conn.rollback();
      conn.release();
      return res.status(409).json({ error: "El login ya está en uso" });
    }

    // Hash de password (placeholder)
    let hashed = password;
    /*
    if (bcrypt) {
      const salt = await bcrypt.genSalt(10);
      hashed = await bcrypt.hash(password, salt);
    }
    */

    // Crear usuario
    const [result] = await conn.query(
      `INSERT INTO usuario (nombre, login, password, idperfil, activo)
       VALUES (?, ?, ?, ?, ?)`,
      [nombre, login, hashed, idperfil, activo ? 1 : 0]
    );

    const idusuario = result.insertId;

    // Si es VENDEDOR (ajusta si tu enum es distinto → aquí supongo idperfil=3)
    if (idperfil === 3) {
      let promotorAsociado = idpromotor;

      if (promotorAsociado) {
        await conn.query(
          `INSERT INTO vendedores (idvendedor, idpromotor)
              VALUES (?, ?)
            ON DUPLICATE KEY UPDATE
              idpromotor = VALUES(idpromotor);`,
          [idusuario, promotorAsociado]
        );
      }
    }

    await conn.commit();
    res.json({ success: true, idusuario });
  } catch (err) {
    await conn.rollback();
    console.error("Error creando usuario:", err);
    res.status(500).json({ error: "Error interno al crear usuario" });
  } finally {
    conn.release();
  }
});




/**
 * @openapi
 * /api/admin/usuarios/{id}:
 *   put:
 *     summary: Actualizar usuario existente
 *     tags: [Admin - Usuarios]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: integer }
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre: { type: string, example: "Juan P. Actualizado" }
 *               password: { type: string, example: "nuevaClave" }
 *               idperfil: 
 *                 type: integer
 *                 enum: [1, 2, 3]
 *               activo: { type: boolean, example: false }
 *               idpromotor: 
 *                 type: integer
 *                 example: 1021
 *                 description: Solo usado para reasignar un vendedor a otro promotor
 *     responses:
 *       200:
 *         description: Usuario actualizado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success: { type: boolean }
 *       404: { description: Usuario no encontrado }
 *       500: { description: Error interno }
 */
app.put('/api/admin/usuarios/:id', appKeyGuard, async (req, res) => {
  const { id } = req.params;
  const { nombre, password, idperfil, activo, idpromotor } = req.body;

  try {
    const [rows] = await pool.query("SELECT * FROM usuario WHERE idusuario = ?", [id]);
    if (rows.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

   /* let hashed = null;
    if (password) {
      hashed = bcrypt
        ? await bcrypt.hash(password, await bcrypt.genSalt(10))
        : password;
    }*/

    await pool.query(
      `UPDATE usuario 
         SET nombre = COALESCE(?, nombre),
             password = COALESCE(?, password),
             idperfil = COALESCE(?, idperfil),
             activo = COALESCE(?, activo)
       WHERE idusuario = ?`,
      [nombre, password, idperfil, activo !== undefined ? (activo ? 1 : 0) : null, id]
    );

    // Si es vendedor y el admin envía nuevo promotor → actualizar relación
    if (idpromotor) {
      await pool.query(
        `INSERT INTO vendedores (idvendedor, idpromotor)
              VALUES (?, ?)
            ON DUPLICATE KEY UPDATE
              idpromotor = VALUES(idpromotor);`,
        [id, idpromotor]
      );
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error actualizando usuario:", err);
    res.status(500).json({ error: "Error interno al actualizar usuario" });
  }
});






//SINCRONIZACION DE LOTERIAS Y RESULTADOS 

const axios = require("axios");

/**
 * @openapi
 * /api/admin/sync-loterias:
 *   post:
 *     summary: Sincroniza loterías desde la API externa hacia la tabla local
 *     tags: [Loterías]
 *     security: [ { appKeyHeader: [] } ]
 *     responses:
 *       200:
 *         description: Loterías sincronizadas correctamente
 *       500:
 *         description: Error al sincronizar loterías
 */
app.post("/api/admin/sync-loterias", appKeyGuard, async (req, res) => {
  try {
    const { data } = await axios.get("https://api-resultadosloterias.com/api/lotteries");

    if (data.status !== "success" || !Array.isArray(data.data)) {
      return res.status(500).json({ error: "Respuesta inválida desde API externa" });
    }

    const conn = await pool.getConnection();
    try {
      for (const lot of data.data) {
        const { name, slug } = lot;

        // Excluir slugs que comiencen por "5ta"
        if (!slug || slug.toLowerCase().startsWith("5ta")) continue;

        // validar si ya existe el slug
        const [exists] = await conn.query(
          "SELECT idloteria FROM loteria WHERE slug = ? LIMIT 1",
          [slug]
        );

        if (exists.length === 0) {
          await conn.query(
            `INSERT INTO loteria (codigo, descrip, activa, serie, slug) 
             VALUES (?, ?, ?, ?, ?)`,
            [slug, name, 1, 0, slug]
          );
        }
      }
      res.json({ success: true, message: "Loterías sincronizadas correctamente" });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Error sync-loterias:", err);
    res.status(500).json({ error: "Error al sincronizar loterías" });
  }
});


/**
 * @openapi
 * /api/admin/sync-resultados/{fecha}:
 *   post:
 *     summary: Sincroniza resultados desde la API externa hacia la tabla local
 *     tags: [Resultados]
 *     security: [ { appKeyHeader: [] } ]
 *     parameters:
 *       - in: path
 *         name: fecha
 *         required: true
 *         schema: { type: string, format: date }
 *         description: Fecha de resultados a sincronizar (YYYY-MM-DD)
 *     responses:
 *       200:
 *         description: Resultados sincronizados correctamente
 *       500:
 *         description: Error al sincronizar resultados
 */
app.post("/api/admin/sync-resultados/:fecha", appKeyGuard, async (req, res) => {
  const { fecha } = req.params; // formato YYYY-MM-DD
  if (!fecha) {
    return res.status(400).json({ error: "Debe enviar la fecha en formato YYYY-MM-DD" });
  }

  try {
    const { data } = await axios.get(
      `https://api-resultadosloterias.com/api/results/${fecha}`
    );

    if (data.status !== "success" || !Array.isArray(data.data)) {
      return res.status(500).json({ error: "Respuesta inválida desde API externa" });
    }
  
    const conn = await pool.getConnection();
    try {
      for (const resul of data.data) {
        const { lottery, slug, result, series } = resul;

        // Excluir slugs que comiencen por "5ta"
        if (!slug || slug.toLowerCase().startsWith("5ta")) continue;

        // buscar idloteria por slug
        const [lotRows] = await conn.query(
          `SELECT a.idloteria 
              FROM loteria a 
              JOIN slugs b ON a.idloteria = b.idloteria  
              WHERE b.slug = ? LIMIT 1`,
          [slug]
        );
        if (lotRows.length === 0) continue; // si la lotería no existe aún, saltamos

        const idloteria = lotRows[0].idloteria;

        // validar si ya existe resultado para esta lotería y fecha
        const [exists] = await conn.query(
          "SELECT idresultado FROM resultado WHERE idloteria = ? AND fecha = ? LIMIT 1",
          [idloteria, fecha]
        );

        if (exists.length === 0) {
          await conn.query(
            `INSERT INTO resultado (fecha, numero, idloteria, publicado, serie) 
             VALUES (?, ?, ?, NOW(), ?)`,
            [fecha, result, idloteria, series]
          );
        }
      }
      res.json({ success: true, message: "Resultados sincronizados correctamente" });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Error sync-resultados:", err);
    res.status(500).json({ error: "Error al sincronizar resultados" });
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
