import { Router } from 'express';
import { pool, bitToBool } from '../db.js';
import { verifyPassword } from '../utils/password.js';

const router = Router();

router.post('/login', async (req, res) => {
  try {
    const { login, password } = req.body || {};
    if (!login || !password) {
      return res.status(400).json({ message: 'Faltan credenciales' });
    }

    const [rows] = await pool.query(
      `SELECT idusuario, idperfil, nombre, login, password, activo
         FROM usuario
        WHERE login = ?
        LIMIT 1`,
      [login]
    );

    if (!rows || rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    const row = rows[0];
    const activo = bitToBool(row.activo);
    if (!activo) {
      return res.status(401).json({ message: 'Usuario inactivo' });
    }

    const ok = await verifyPassword(password, row.password || '');
    if (!ok) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }

    return res.json({
      idusuario: row.idusuario,
      idperfil: row.idperfil,
      nombre: row.nombre,
      login: row.login
    });
  } catch (err) {
    console.error('auth/login error', err);
    return res.status(500).json({ message: 'Error interno' });
  }
});

export default router;
