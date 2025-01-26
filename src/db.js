


const mysql = require('mysql2');



// Configuración del pool de conexiones
const pool = mysql.createPool({
    host: '147.93.113.198',
    user: 'root',
    password: 'PuS4ENP0tvqLuWQGkG3CQ06rpzi5Q63VX3PJimxnCz62lE7M4wRsXPf92uLnil1N',
    database: 'hidraulibombas',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 100,  // Aumentado para permitir más conexiones simultáneas si es necesario
    queueLimit: 0,  // Sin límite en la cola de conexiones
    connectTimeout: 5000  // Reducido a 5 segundos para intentar conexiones más rápidas
}).promise();  // Esto conversión que utiliza promesas




module.exports = pool;