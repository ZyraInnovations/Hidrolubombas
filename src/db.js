const mysql = require('mysql2');

// Configuración del pool de conexiones
const pool = mysql.createPool({
    host: '35.238.176.167',
    user: 'julian',
    password: '1034277764C',
    database: 'cerceta',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 100,
    queueLimit: 0,
    connectTimeout: 10000,
    multipleStatements: true,
    timezone: 'Z'
}).promise();

// Función para ejecutar consultas con manejo de errores y reconexiones
async function executeQuery(query, params = []) {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.query(query, params);
        return rows;
    } catch (error) {
        console.error('Error ejecutando consulta:', error);
        if (error.code === 'PROTOCOL_CONNECTION_LOST' || error.code === 'ECONNRESET') {
            console.log('Intentando reconectar...');
            return executeQuery(query, params);
        }
        throw error;
    } finally {
        if (connection) connection.release();
    }
}

// Monitoreo del estado del pool con conexiones activas
setInterval(async () => {
    try {
        const [result] = await pool.query('SELECT 1'); // Consulta simple para verificar actividad
        console.log('El pool está activo:', result);
    } catch (error) {
        console.error('Error verificando el estado del pool:', error);
    }
}, 10000);

process.on('uncaughtException', (err) => {
    console.error('Excepción no capturada:', err);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Promesa rechazada no manejada:', promise, 'razón:', reason);
});

module.exports = {
    pool,
    executeQuery
};
