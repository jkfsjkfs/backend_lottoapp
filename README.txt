1. Crea una base de datos llamada `rifa_db`
2. Ejecuta esta consulta para crear la tabla de registros:

CREATE TABLE registros (
  id INT AUTO_INCREMENT PRIMARY KEY,
  numero VARCHAR(4),
  nombre VARCHAR(100),
  telefono VARCHAR(20),
  fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

3. Configura tu archivo .env si usas credenciales distintas para MySQL
4. Ejecuta `npm install` y luego `npm start`