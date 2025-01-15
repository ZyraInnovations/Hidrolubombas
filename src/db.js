


const mysql = require('mysql2');



// Configuración del pool de conexiones
const pool = mysql.createPool({
    host: '34.44.185.78',
    user: 'julian',
    password: '1034277764C',
    database: 'hidraulibombas',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 100,  // Aumentado para permitir más conexiones simultáneas si es necesario
    queueLimit: 0,  // Sin límite en la cola de conexiones
    connectTimeout: 5000  // Reducido a 5 segundos para intentar conexiones más rápidas
}).promise();  // Esto convierte el pool en una versión que utiliza promesas




module.exports = pool;