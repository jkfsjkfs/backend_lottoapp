// swagger.js
const swaggerJSDoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Lotto API',
      version: '1.0.0',
      description: 'API de Lotto (registros, consulta de números, etc.)',
    },
    servers: [
      { url: 'http://localhost:3001', description: 'Local' },
      { url: 'https://backend-lottoapp-ijsj.onrender.com/', description: 'Producción' },

    ],
  },
  // Ajusta las rutas de tus archivos donde están las anotaciones @openapi
  apis: ['./app.js', './routes/**/*.js'],
};

module.exports = swaggerJSDoc(options);
