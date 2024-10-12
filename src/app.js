const express = require('express');
const session = require('express-session');
const hbs = require('hbs');
const pool = require('./db'); // Importamos la configuración de la base de datos
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
// Middleware para analizar el cuerpo de las solicitudes
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configurar la sesión
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 'secure' debe ser 'true' si usas HTTPS
}));
// Configurar el motor de plantillas
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));  // Asegúrate de que apunte correctamente a tu carpeta de vistas
app.use(express.static(__dirname + '/public'));

// Middleware para parsing
app.use(express.urlencoded({ extended: false }));


// Ruta para mostrar el formulario de login
app.get('/login', (req, res) => {
    res.render('login/login');
});

// Asegúrate de que Express pueda manejar datos en formato JSON
app.use(express.json());


// Ruta para manejar el login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Query to check if user exists with the given email and password
        const [results] = await pool.query('SELECT * FROM usuarios_hidro WHERE email = ? AND password = ?', [email, password]);

        if (results.length > 0) {
            // Store user data in session
            req.session.user = results[0];  // Store the entire user object
            req.session.name = results[0].nombre;  // Save the user name to session
            req.session.loggedin = true;  // Set logged-in status
            req.session.roles = results[0].role;  // Save roles in session

            const role = results[0].role;  // Fetch user role

            // Redirect based on the user's role
            if (role === 'admin') {
                return res.redirect('/menuAdministrativo');
            } else if (role === 'tecnico') {
                return res.redirect('/tecnico');
            } else if (role === 'cliente') {
                return res.redirect('/cliente');
            }
        } else {
            // Render login page with error message if credentials are incorrect
            res.render('login/login', { error: 'Correo o contraseña incorrectos' });
        }
    } catch (err) {
        // Handle errors and send a 500 response in case of any database or server issues
        res.status(500).json({ error: err.message });
    }
});



// Ruta para el menú administrativo
app.get('/geolocalizacion', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Use user session data
        res.render('administrativo/mapa/ver_mapa.hbs', { nombreUsuario });
    } else {
        res.redirect('/login');
    }
});



// Ruta para el menú administrativo
app.get('/figma', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Use user session data
        res.render('administrativo/figma.hbs', { nombreUsuario });
    } else {
        res.redirect('/login');
    }
});







// Ruta para manejar el cierre de sesión
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.redirect('/login');  // Redirige al usuario a la página de login
    });
});






const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid'); // Utiliza UUID para generar IDs únicos

// Configurar el transporter con nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'nexus.innovationss@gmail.com', // Coloca tu correo electrónico
        pass: 'dhmtnkcehxzfwzbd' // Coloca tu contraseña de correo electrónico
    },
    messageId: uuidv4(), // Genera un Message-ID único para cada correo enviado
});

const crypto = require('crypto'); // Importa el módulo crypto





app.get("/menuAdministrativo", (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.name || req.session.user.name;  // Use the session name or fallback
        console.log(`El usuario ${nombreUsuario} está autenticado.`);
        req.session.nombreGuardado = nombreUsuario; // Guarda el nombre en la sesión

        const rolesString = req.session.roles;
        const roles = Array.isArray(rolesString) ? rolesString : [];

        const jefe = roles.includes('jefe');
        const empleado = roles.includes('empleado');

        res.render("administrativo/menuadministrativo.hbs", {
            name: nombreUsuario, // Pass the name to the template
            jefe,
            empleado
        });
    } else {
        res.redirect("/login");
    }
});





const multer = require('multer');






// Configuración de multer para manejar la subida de archivos
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });



// Ruta para el menú administrativo - Mostrar formulario para nuevo usuario
app.get('/nuevousuario', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario
        res.render('administrativo/usuarios/crear_usuarios.hbs', { nombreUsuario });
    } else {
        res.redirect('/login');
    }
});

// Ruta para manejar la creación de un nuevo usuario
app.post('/agregar_usuario', (req, res) => {
    if (req.session.loggedin === true) {
        const { nombre, email, password, role } = req.body;
        console.log('Datos recibidos:', { nombre, email, password, role });

        if (!nombre || !email || !password || !role) {
            console.log('Campos faltantes');
            return res.status(400).send('Todos los campos son obligatorios');
        }

        pool.getConnection((err, connection) => {
            if (err) {
                console.error('Error al obtener la conexión:', err);
                return res.status(500).send('Error en el servidor');
            }

            connection.query('INSERT INTO usuarios_hidro (nombre, email, password, role) VALUES (?, ?, ?, ?)', 
            [nombre, email, password, role], (err, results) => {
                connection.release(); // Liberar la conexión

                if (err) {
                    console.error('Error al agregar el usuario:', err);
                    res.status(500).send('Error al agregar el usuario');
                } else {
                    console.log('Usuario agregado con éxito');
                    res.redirect('/consultar_usuarios');
                }
            });
        });
    } else {
        res.redirect('/login');
    }
});

const mysql = require('mysql2');

app.use(express.urlencoded({ extended: true })); // Esto es importante para manejar datos de formularios


// Configuración de la base de datos
const db = mysql.createConnection({
    host: "34.66.173.227",
    user: "soporte",
    password: "1034277764C",
    database: "viancoapp",
    port: 3306,
    waitForConnections: true,
    connectionLimit: 100,  // Aumentado para permitir más conexiones simultáneas si es necesario
    queueLimit: 0,  // Sin límite en la cola de conexiones
    connectTimeout: 5000  // Reducido a 5 segundos para intentar conexiones más rápidas
  });
  
  // Conectar a la base de datos
  db.connect((err) => {
    if (err) {
      console.error('Error conectando a la base de datos:', err);
    } else {
      console.log('Conectado a la base de datos.');
    }
  });
  




// Function to convert base64 string to a Buffer
function bufferFromBase64(base64Data) {
    const base64String = base64Data.split(';base64,').pop();
    return Buffer.from(base64String, 'base64');
}



  // Ruta para manejar la inserción de datos del formulario
  app.post('/insertar-datos', upload.none(), (req, res) => {
    const datos = req.body;
      // Convert the base64 strings to buffers
      const firmaTecnicoBlob = bufferFromBase64(datos.firma_tecnico);
      const firmaSupervisorBlob = bufferFromBase64(datos.firma_supervisor);
    // Crear la consulta SQL
    const query = `INSERT INTO mantenimiento_hidro (
      cliente, equipo, tecnico, hora_entrada, hora_salida, fecha, numero,
      variador_b1, variador_b2, variador_b3, variador_b4, precarga,
      guarda_motor_b11, guarda_motor_b22, guarda_motor_b33, guarda_motor_b44,
      mutelillas_b1, mutelillas_b2, mutelillas_b3, mutelillas_b4, flotador_mecanico,
      breaker_b1, breaker_b2, breaker_b3, breaker_b4, piloto_b1, piloto_b2,
      piloto_b3, piloto_b4, valvulas_succion, muletillas_b1, muletillas_b2,
      muletillas_b3, muletillas_b4, contactores_b1, contactores_b2, contactores_b3,
      contactores_b4, tanque_hidro, contacores_b1, contacores_b2, contacores_b3,
      contacores_b4, presostatos_b1, presostatos_b2, presostatos_b3, presostatos_b4,
      cheques, flotador_electricos_b1, flotador_electricos_b2, flotador_electricos_b3,
      flotador_electricos_b4, alternador_b1, alternador_b2, alternador_b3, alternador_b4,
      presion_linea, conexiones_b11, conexiones_b22, conexiones_b33, conexiones_b44,
      guarda_motor_b1, guarda_motor_b2, guarda_motor_b3, guarda_motor_b4, registros,
      amperaje_b11, amperaje_b22, amperaje_b33, amperaje_b44, temporizador_b1,
      temporizador_b2, temporizador_b3, temporizador_b4, membrana, voltaje_b11,
      voltaje_b22, voltaje_b33, voltaje_b44, rele_termico_b1, rele_termico_b2,
      rele_termico_b3, rele_termico_b4, manometro, sierena_b1, sierena_b2,
      sierena_b3, sierena_b4, flotador_electrico_b1, flotador_electrico_b2,
      flotador_electrico_b3, flotador_electrico_b4, cargador_aire, rele_terminco_b1,
      rele_terminco_b2, rele_terminco_b3, rele_terminco_b4, conexiones_b1,
      conexiones_b2, conexiones_b3, conexiones_b4, tanque_reserva, residuos_b1,
      residuos_b2, residuos_b3, residuos_b4, amperaje_b1, amperaje_b2, amperaje_b3,
      amperaje_b4, flauta_descarga, voltaje_b1, voltaje_b2, voltaje_b3, voltaje_b4,
      rodamientos_m1, rodamientos_m2, rodamientos_m3, rodamientos_m4, impulsor_m1,
      impulsor_m2, impulsor_m3, impulsor_m4, cambio, falla, pendiente, diagnostico,
      verificado, operando, casquillo_b1, casquillo_b2, casquillo_b3, casquillo_b4,
      sello_mecanico_b1, sello_mecanico_b2, sello_mecanico_b3, sello_mecanico_b4,
      empaque_b1, empaque_b2, empaque_b3, empaque_b4, empaque_2_b1, empaque_2_b2,
      empaque_2_b3, empaque_2_b4, ventilador_b1, ventilador_b2, ventilador_b3,
      ventilador_b4, carcasa_b1, carcasa_b2, carcasa_b3, carcasa_b4, bornes_b1,
      bornes_b2, bornes_b3, bornes_b4, casquillo_b11, casquillo_b22, casquillo_b33,
      casquillo_b44, bobinado_b1, bobinado_b2, bobinado_b3, bobinado_b4,
      partes_para_cambio, observaciones,firma_tecnico, firma_supervisor,tipo_de_mantenimiento
    ) VALUES ?`;
  
    // Extraer valores del objeto req.body
    const values = [
      [
        datos.cliente, datos.equipo, datos.tecnico, datos.hora_entrada, datos.hora_salida,
        datos.fecha, datos.numero, datos.variador_b1, datos.variador_b2, datos.variador_b3,
        datos.variador_b4, datos.precarga, datos.guarda_motor_b11, datos.guarda_motor_b22,
        datos.guarda_motor_b33, datos.guarda_motor_b44, datos.mutelillas_b1,
        datos.mutelillas_b2, datos.mutelillas_b3, datos.mutelillas_b4, datos.flotador_mecanico,
        datos.breaker_b1, datos.breaker_b2, datos.breaker_b3, datos.breaker_b4, datos.piloto_b1,
        datos.piloto_b2, datos.piloto_b3, datos.piloto_b4, datos.valvulas_succion,
        datos.muletillas_b1, datos.muletillas_b2, datos.muletillas_b3, datos.muletillas_b4,
        datos.contactores_b1, datos.contactores_b2, datos.contactores_b3, datos.contactores_b4,
        datos.tanque_hidro, datos.contacores_b1, datos.contacores_b2, datos.contacores_b3,
        datos.contacores_b4, datos.presostatos_b1, datos.presostatos_b2, datos.presostatos_b3,
        datos.presostatos_b4, datos.cheques, datos.flotador_electricos_b1, datos.flotador_electricos_b2,
        datos.flotador_electricos_b3, datos.flotador_electricos_b4, datos.alternador_b1,
        datos.alternador_b2, datos.alternador_b3, datos.alternador_b4, datos.presion_linea,
        datos.conexiones_b11, datos.conexiones_b22, datos.conexiones_b33, datos.conexiones_b44,
        datos.guarda_motor_b1, datos.guarda_motor_b2, datos.guarda_motor_b3, datos.guarda_motor_b4,
        datos.registros, datos.amperaje_b11, datos.amperaje_b22, datos.amperaje_b33,
        datos.amperaje_b44, datos.temporizador_b1, datos.temporizador_b2, datos.temporizador_b3,
        datos.temporizador_b4, datos.membrana, datos.voltaje_b11, datos.voltaje_b22,
        datos.voltaje_b33, datos.voltaje_b44, datos.rele_termico_b1, datos.rele_termico_b2,
        datos.rele_termico_b3, datos.rele_termico_b4, datos.manometro, datos.sierena_b1,
        datos.sierena_b2, datos.sierena_b3, datos.sierena_b4, datos.flotador_electrico_b1,
        datos.flotador_electrico_b2, datos.flotador_electrico_b3, datos.flotador_electrico_b4,
        datos.cargador_aire, datos.rele_terminco_b1, datos.rele_terminco_b2, datos.rele_terminco_b3,
        datos.rele_terminco_b4, datos.conexiones_b1, datos.conexiones_b2, datos.conexiones_b3,
        datos.conexiones_b4, datos.tanque_reserva, datos.residuos_b1, datos.residuos_b2,
        datos.residuos_b3, datos.residuos_b4, datos.amperaje_b1, datos.amperaje_b2,
        datos.amperaje_b3, datos.amperaje_b4, datos.flauta_descarga, datos.voltaje_b1,
        datos.voltaje_b2, datos.voltaje_b3, datos.voltaje_b4, datos.rodamientos_m1,
        datos.rodamientos_m2, datos.rodamientos_m3, datos.rodamientos_m4, datos.impulsor_m1,
        datos.impulsor_m2, datos.impulsor_m3, datos.impulsor_m4, datos.cambio, datos.falla,
        datos.pendiente, datos.diagnostico, datos.verificado, datos.operando,
        datos.casquillo_b1, datos.casquillo_b2, datos.casquillo_b3, datos.casquillo_b4,
        datos.sello_mecanico_b1, datos.sello_mecanico_b2, datos.sello_mecanico_b3,
        datos.sello_mecanico_b4, datos.empaque_b1, datos.empaque_b2, datos.empaque_b3,
        datos.empaque_b4, datos.empaque_2_b1, datos.empaque_2_b2, datos.empaque_2_b3,
        datos.empaque_2_b4, datos.ventilador_b1, datos.ventilador_b2, datos.ventilador_b3,
        datos.ventilador_b4, datos.carcasa_b1, datos.carcasa_b2, datos.carcasa_b3,
        datos.carcasa_b4, datos.bornes_b1, datos.bornes_b2, datos.bornes_b3,
        datos.bornes_b4, datos.casquillo_b11, datos.casquillo_b22, datos.casquillo_b33,
        datos.casquillo_b44, datos.bobinado_b1, datos.bobinado_b2, datos.bobinado_b3,
        datos.bobinado_b4, datos.partes_para_cambio, datos.observaciones,  firmaTecnicoBlob, firmaSupervisorBlob,datos.tipo_de_manteninimiento
      ]
    ];
  
    // Ejecutar la consulta para insertar los datos
    db.query(query, [values], (err, result) => {
      if (err) {
        console.error('Error al insertar los datos:', err);
        res.status(500).send('Error al insertar los datos');
      } else {
        res.send('Datos insertados correctamente');
      }
    });
  });
  


// Ruta para consultar los usuarios
app.get('/consultar_usuarios', async (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name;
        try {
            // Consulta para obtener todos los usuarios
            const [results] = await pool.query('SELECT id, nombre, email, role FROM usuarios_hidro   ');
            // Renderiza la plantilla con los resultados
            res.render('administrativo/usuarios/consulta_usuarios.hbs', { nombreUsuario, usuarios: results });
        } catch (err) {
            console.error('Error al consultar la base de datos:', err);
            res.status(500).send('Error en el servidor');
        }
    } else {
        res.redirect('/login');
    }
});







app.use(bodyParser.json()); // Para parsear JSON
app.use(bodyParser.urlencoded({ extended: true })); // Para parsear datos de formularios










// Ruta para el menú administrativo - Mostrar formulario para nuevo usuario
app.get('/realizar_informe', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario
        res.render('administrativo/informes/crear_informe.hbs', { nombreUsuario });
    } else {
        res.redirect('/login');
    }
});



// Ruta para ver informes
app.get('/ver_informe', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name;
        const informeId = req.query.id; // Obtener el ID del informe desde el formulario

        if (!informeId) {
            res.render('administrativo/informes/consulta_informe.hbs', {
                nombreUsuario,
                mensajeError: 'Por favor, ingrese un ID válido para buscar el informe.'
            });
            return;
        }

        // Realizar la consulta en la base de datos
        const query = 'SELECT * FROM mantenimiento_hidro WHERE id = ?';
        db.query(query, [informeId], (err, results) => {
            if (err) {
                console.error('Error al realizar la consulta:', err);
                res.status(500).send('Error en el servidor');
            } else if (results.length > 0) {
                const informe = results[0];

                // Convertir las firmas a Base64 si existen
                if (informe.firma_tecnico) {
                    informe.firma_tecnico = Buffer.from(informe.firma_tecnico).toString('base64');
                }
                if (informe.firma_supervisor) {
                    informe.firma_supervisor = Buffer.from(informe.firma_supervisor).toString('base64');
                }

                // Renderizar la vista con los datos del informe encontrado
                res.render('administrativo/informes/consulta_informe.hbs', {
                    nombreUsuario,
                    informe
                });
            } else {
                res.render('administrativo/informes/consulta_informe.hbs', {
                    nombreUsuario,
                    mensajeError: 'No se encontró ningún informe con el ID proporcionado.'
                });
            }
        });
    } else {
        res.redirect('/login');
    }
});

app.get('/api/informes-count', (req, res) => {
    const query = 'SELECT COUNT(*) AS count FROM mantenimiento_hidro';

    db.query(query, (error, results) => {
        if (error) {
            console.error('Error al contar los informes:', error);
            return res.status(500).json({ error: 'Error al contar los informes' });
        }
        res.json({ count: results[0].count });
    });
});




app.get('/api/tecnicos-count', (req, res) => {
    const query = 'SELECT COUNT(*) AS count FROM usuarios_hidro WHERE role = "tecnico"';

    db.query(query, (error, results) => {
        if (error) {
            console.error('Error al contar los técnicos:', error);
            return res.status(500).json({ error: 'Error al contar los técnicos' });
        }
        res.json({ count: results[0].count });
    });
});


app.get('/api/mantenimientos-por-mes', (req, res) => {
    const query = `
        SELECT 
            fecha,
            tipo_de_mantenimiento,
            COUNT(*) AS count
        FROM mantenimiento_hidro
        GROUP BY fecha, tipo_de_mantenimiento
        ORDER BY fecha
    `;
    
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error al obtener los datos de mantenimiento:', error);
            return res.status(500).json({ error: 'Error al obtener los datos' });
        }
        res.json(results);
    });
});


app.get('/api/clientes-count', (req, res) => {
    const query = `SELECT COUNT(DISTINCT cliente) AS count FROM mantenimiento_hidro`;

    db.query(query, (error, results) => {
        if (error) {
            console.error('Error al obtener el conteo de clientes:', error);
            return res.status(500).json({ error: 'Error al obtener el conteo de clientes' });
        }
        res.json(results[0]);
    });
});


// Iniciar el servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});