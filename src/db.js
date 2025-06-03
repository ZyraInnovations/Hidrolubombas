


const mysql = require('mysql2');



// Configuración del pool de conexiones
const pool = mysql.createPool({
    host: '147.93.113.198',
    user: 'root',
    password: 'w2gF5JMh69BteTQo063lU2UgNDSikeglo35gMb5VDBPdKZQZfdNEdmYP4yliNHo9',
    database: 'default',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 1000,  // Aumentado para permitir más conexiones simultáneas si es necesario
    queueLimit: 0,  // Sin límite en la cola de conexiones
    connectTimeout: 10000  // Reducido a 5 segundos para intentar conexiones más rápidas
}).promise();  // Esto conversión que utiliza promesas




module.exports = pool;