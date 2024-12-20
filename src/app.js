const express = require('express');
const session = require('express-session');
const pool = require('./db'); // Importamos la configuración de la base de datos
const path = require('path');
const bodyParser = require('body-parser');
const moment = require('moment-timezone');
const exphbs = require('express-handlebars');
const hbs = require('hbs');

const app = express();
// Middleware para analizar el cuerpo de las 

// Configura los límites de tamaño de carga para JSON y URL-encoded
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(bodyParser.json({ limit: '50mb' }));  // Limitar el tamaño de la carga JSON a 50MB
// Configurar la sesión
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 'secure' debe ser 'true' si usas HTTPS
}));




// Crear el motor de plantillas con Handlebars y registrar el helper

// Registrar helpers globales
hbs.registerHelper('eq', (arg1, arg2) => {
    return arg1 == arg2; // Comparación flexible
});

hbs.registerHelper('selectedRole', (currentRole, optionValue) => {
    return currentRole === optionValue ? 'selected' : ''; // Retorna 'selected' si coincide
});


// Configuración del motor de plantillas para Express
app.set('view engine', 'hbs');  // Usamos 'hbs' para las vistas
app.set('views', path.join(__dirname, 'views'));  // Asegúrate de que apunte a la carpeta de vistas

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

app.use(express.urlencoded({ extended: false }));




app.get('/', (req, res) => {
    res.redirect('/login');
});


// Ruta para mostrar el formulario de login
app.get('/login', (req, res) => {
    res.render('login/login');
});

// Asegúrate de que Express pueda manejar datos en formato JSON
app.use(express.json());






app.use('/manifest.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.sendFile(__dirname + '/manifest.json');
});





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
                return res.redirect('/menutecnicos');
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
        res.render('administrativo/mapa/ver_mapa.hbs', { nombreUsuario,layout: 'layouts/nav_admin.hbs' });
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
        user: 'ingeoperativos@gmail.com', // Coloca tu correo electrónico
        pass: 'gwkdpbzedomryivi' // Coloca tu contraseña de correo electrónico
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
            layout: 'layouts/nav_admin.hbs',
            empleado
        });
    } else {
        res.redirect("/login");
    }
});













app.get("/menutecnicos", (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.name || req.session.user.name;  // Use the session name or fallback
        console.log(`El usuario ${nombreUsuario} está autenticado.`);
        req.session.nombreGuardado = nombreUsuario; // Guarda el nombre en la sesión

        const rolesString = req.session.roles;
        const roles = Array.isArray(rolesString) ? rolesString : [];

        const jefe = roles.includes('jefe');
        const empleado = roles.includes('empleado');

        res.render("tecnicos/menu_tecnicos.hbs", {
            name: nombreUsuario, // Pass the name to the template
            jefe,
            layout: 'layouts/nav_tecnico.hbs'
        });
    } else {
        res.redirect("/login");
    }
});









const multer = require('multer');
const storage = multer.memoryStorage(); // Almacenar archivos en la memoria temporalmente
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


const mysql = require('mysql2');

app.use(express.urlencoded({ extended: true })); // Esto es importante para manejar datos de formularios


// Configuración de la base de datos
const db = mysql.createConnection({
    host: '34.56.87.125',
    user: 'Julian',
    password: "1034277764C",
    database: 'cerceta',
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




// Ruta combinada para insertar datos y enviar correo
app.post('/procesar-datos', upload.fields([
    { name: 'imagen', maxCount: 1 },    // Imagen generada obligatoria
    { name: 'fotos', maxCount: 10 }    // Imágenes adicionales opcionales
]), (req, res) => {
    const datos = req.body;
    const accion = datos.accion; // Asegúrate de definir "accion" al inicio
 
  
    // Convertir las firmas a buffers
    const firmaSupervisorBlob = bufferFromBase64(datos.firma_supervisor);

    // Consulta SQL para insertar datos
    const query = `INSERT INTO mantenimiento_hidro (
        cliente, equipo, tecnico,torre, hora_entrada, hora_salida, fecha, numero,
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
        partes_para_cambio, observaciones, firma_supervisor,tipo_de_mantenimiento,Correo
      ) VALUES ?`;

      const values = [
        [
          datos.cliente, datos.equipo, datos.tecnico,datos.torre, datos.hora_entrada, datos.hora_salida,
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
          datos.bobinado_b4, datos.partes_para_cambio, datos.observaciones, firmaSupervisorBlob,datos.tipo_de_mantenimiento,datos.Correo
        ]
      ];

    // Insertar los datos
    db.query(query, [values], (err, result) => {
        if (err) {
            console.error('Error al insertar los datos:', err);
            return res.status(500).json({ success: false, message: 'Error al insertar los datos' });
        }

        console.log('Datos insertados correctamente:', result);

        const insertedId = result.insertId;

        if (accion === 'guardar_y_enviar') {
            const correoDestino = datos.Correo;
            let imagenHTML = req.files['imagen'] ? req.files['imagen'][0] : null;
            let imagenesAdjuntas = req.files['fotos'] || [];

            if (!imagenHTML) {
                return res.status(400).json({ success: false, message: 'La imagen generada es obligatoria.' });
            }

            const attachments = [
                {
                    filename: 'informe_mantenimiento.jpg',
                    content: imagenHTML.buffer
                }
            ];

            imagenesAdjuntas.forEach((imagen, index) => {
                attachments.push({
                    filename: `imagen_${index + 1}.jpg`,
                    content: imagen.buffer
                });
            });

            const mailOptions = {
                from: 'ingeoperativos@gmail.com',
                to: correoDestino,
                subject: `Informe de Mantenimiento N° ${insertedId}`, // Agrega el número de informe al asunto
                text: 'Adjunto se encuentra el informe de mantenimiento en formato imagen, junto con las imágenes seleccionadas.',
                attachments: attachments
            };

            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    console.error('Error al enviar el correo:', error);
                    return res.status(500).json({ success: false, message: 'Error al enviar el correo' });
                }
            
                console.log('Correo enviado:', info);
                res.status(200).json({
                    success: true,
                    message: `Datos insertados y correo enviado con éxito. Su informe se guardó correctamente con el número: ${insertedId}.`
                });
            });
        } else {
            res.status(200).json({
                success: true,
                message: `Su informe se guardó correctamente con el número: ${insertedId}.`
            });
        }
    });
});



















app.get('/consultar_usuarios', async (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name;
        try {
            // Consulta de usuarios con foto y firma
            const [results] = await pool.query('SELECT id, nombre, email, password, role, foto, firma FROM usuarios_hidro');

            // Convierte las fotos y las firmas a Base64 para mostrar en el frontend
            const usuarios = results.map(user => ({
                ...user,
                foto: user.foto ? `data:image/jpeg;base64,${user.foto.toString('base64')}` : null,
                firma: user.firma // La firma ya está en Base64, así que no necesita conversión
            }));

            res.render('administrativo/usuarios/consulta_usuarios.hbs', { 
                nombreUsuario, 
                layout: 'layouts/nav_admin.hbs', 
                usuarios 
            });
        } catch (err) {
            console.error('Error al consultar la base de datos:', err);
            res.status(500).send('Error en el servidor.');
        }
    } else {
        res.redirect('/login');
    }
});




app.get('/eliminar_usuario/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM usuarios_hidro WHERE id = ?', [id]);
        res.redirect('/consultar_usuarios');
    } catch (err) {
        console.error('Error al eliminar usuario:', err);
        res.status(500).send('Error en el servidor');
    }
});




app.get('/editar_usuario/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const [user] = await pool.query('SELECT * FROM usuarios_hidro WHERE id = ?', [id]);
        if (user.length === 0) {
            return res.status(404).send('Usuario no encontrado.');
        }
          // Convertir la foto BLOB a base64 si existe
          if (user[0].foto) {
            user[0].foto = `data:image/jpeg;base64,${user[0].foto.toString('base64')}`;
        }

        res.render('administrativo/usuarios/editar_usuario.hbs', {
            layout: 'layouts/nav_admin.hbs', 

            usuario: user[0] // Pasar el usuario al template
            
        });
    } catch (err) {
        console.error('Error al cargar usuario:', err);
        res.status(500).send('Error del servidor.');
    }
});












app.post('/editar_usuario/:id', upload.single('foto'), async (req, res) => {
    const { id } = req.params;
    const { nombre, email, password, role, firma } = req.body;
    const foto = req.file;

    try {
        const updates = [];
        const values = [];

        if (nombre) {
            updates.push('nombre = ?');
            values.push(nombre);
        }
        if (email) {
            updates.push('email = ?');
            values.push(email);
        }
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updates.push('password = ?');
            values.push(hashedPassword);
        }
        if (role) {
            updates.push('role = ?');
            values.push(role);
        }
        if (foto) {
            updates.push('foto = ?');
            values.push(foto.buffer);
        }
        if (firma) {
            updates.push('firma = ?');
            values.push(firma);
        }

        values.push(id);

        const query = `UPDATE usuarios_hidro SET ${updates.join(', ')} WHERE id = ?`;
        await pool.query(query, values);

        res.redirect('/consultar_usuarios');
    } catch (err) {
        console.error('Error al actualizar usuario:', err);
        res.status(500).send('Error en el servidor');
    }
});








app.use(bodyParser.json()); // Para parsear JSON
app.use(bodyParser.urlencoded({ extended: true })); // Para parsear datos de formularios








app.get('/realizar_informe', async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.user.id;
            const userQuery = 'SELECT role FROM usuarios_hidro WHERE id = ?';
            const [userRows] = await pool.query(userQuery, [userId]);

            if (userRows.length > 0) {
                const nombreUsuario = req.session.user.name;
                const layout = userRows[0].role === 'admin' ? 'layouts/nav_admin.hbs' : 'layouts/nav_tecnico.hbs';

                // Consulta para obtener la lista de clientes
                const clientsQuery = 'SELECT id, nombre FROM clientes_hidrolubombas';
                const [clientes] = await pool.query(clientsQuery);

                // Consulta para obtener la lista de técnicos
                const tecnicosQuery = `
                SELECT id, nombre FROM usuarios_hidro WHERE role = "tecnico"
                UNION
                SELECT id, nombre FROM usuarios_hidro WHERE id = 6
            `;
            const [tecnicos] = await pool.query(tecnicosQuery)
                // Renderiza la vista con los datos necesarios
                res.render('administrativo/informes/crear_informe.hbs', {
                    nombreUsuario,
                    layout,
                    clientes,
                    tecnicos // Enviar lista de técnicos a la vista
                });
            } else {
                res.redirect('/login');
            }
        } catch (error) {
            console.error('Error al cargar la página de informe:', error);
            res.status(500).send('Error interno del servidor');
        }
    } else {
        res.redirect('/login');
    }
});



















app.get('/get_cliente_correo/:id', async (req, res) => {
    try {
        const clientId = req.params.id; // ID del cliente
        const query = 'SELECT correo FROM clientes_hidrolubombas WHERE id = ?';
        const [rows] = await pool.query(query, [clientId]);

        if (rows.length > 0) {
            res.json({ success: true, correo: rows[0].correo });
        } else {
            res.json({ success: false, message: 'Cliente no encontrado' });
        }
    } catch (error) {
        console.error('Error al obtener el correo del cliente:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});





app.get('/consulta_informe', (req, res) => {
    if (req.session.loggedin === true) {
        const userId = req.session.user.id; // Obtén el ID del usuario desde la sesión
        const nombreUsuario = req.session.user.name;

        // Consulta el rol del usuario en la base de datos
        const roleQuery = 'SELECT role FROM usuarios_hidro WHERE id = ?';
        db.query(roleQuery, [userId], (err, roleResults) => {
            if (err) {
                console.error('Error al obtener el rol del usuario:', err);
                res.status(500).send('Error en el servidor');
            } else if (roleResults.length > 0) {
                const userRole = roleResults[0].role;
                const layout = userRole === 'admin' ? 'layouts/nav_admin.hbs' : 'layouts/nav_tecnico.hbs';

                // Obtener la lista de clientes
                const clientesQuery = 'SELECT id, nombre FROM clientes_hidrolubombas';
                db.query(clientesQuery, (err, clientes) => {
                    if (err) {
                        console.error('Error al obtener los clientes:', err);
                        res.status(500).send('Error en el servidor');
                    } else {
                        // Obtener la lista de técnicos
                        const query = `
                            SELECT DISTINCT m.tecnico, u.nombre AS tecnico_name 
                            FROM mantenimiento_hidro m
                            LEFT JOIN usuarios_hidro u ON m.tecnico = u.id
                        `;
                        db.query(query, (err, results) => {
                            if (err) {
                                console.error('Error al obtener la lista de técnicos:', err);
                                res.status(500).send('Error en el servidor');
                            } else {
                                // Extraer los nombres de los técnicos de los resultados
                                const tecnicos = results.map(row => ({
                                    id: row.tecnico,
                                    name: row.tecnico_name
                                }));

                                // Renderizar la vista
                                res.render('administrativo/informes/consulta_informe.hbs', {
                                    nombreUsuario,
                                    layout,
                                    tecnicos,
                                    clientes // Pasamos la lista de clientes
                                });
                            }
                        });
                    }
                });
            } else {
                res.redirect('/login'); // Si no hay rol, redirige al login
            }
        });
    } else {
        res.redirect('/login');
    }
});




app.get('/ver_informe', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name;
        let informeId = req.query.id;

        if (Array.isArray(informeId)) {
            informeId = informeId.find(id => id !== ''); // Toma el primer valor válido
        }

        console.log('ID recibido:', informeId);

        // Validar que el ID sea un número válido
        if (!informeId || !/^\d+$/.test(informeId)) {
            obtenerListas((err, tecnicos, clientes) => {
                if (err) {
                    res.status(500).send('Error en el servidor.');
                } else {
                    res.render('administrativo/informes/consulta_informe.hbs', {
                        layout: 'layouts/nav_admin.hbs',
                        nombreUsuario,
                        tecnicos,
                        clientes,
                        mensajeError: 'Por favor, ingresa un ID válido para buscar el informe.'
                    });
                }
            });
            return;
        }

        // Consulta para obtener el informe con firmas convertidas a Base64
        const query = `
            SELECT *, 
                TO_BASE64(firma_tecnico) AS firma_tecnico_base64, 
                TO_BASE64(firma_supervisor) AS firma_supervisor_base64 
            FROM mantenimiento_hidro 
            WHERE id = ?
        `;
        db.query(query, [informeId], (err, results) => {
            if (err) {
                console.error('Error al realizar la consulta:', err);
                res.status(500).send('Error en el servidor.');
            } else if (results.length > 0) {
                const informe = results[0];

                // Asignar las firmas en formato Base64 al objeto `informe`
                informe.firma_tecnico = informe.firma_tecnico_base64;
                informe.firma_supervisor = informe.firma_supervisor_base64;

                // Obtener el cliente relacionado con la foto
                const clienteQuery = `
                    SELECT nombre, TO_BASE64(foto) AS foto_base64 
                    FROM clientes_hidrolubombas 
                    WHERE id = ?
                `;
                db.query(clienteQuery, [informe.cliente], (err, clienteResult) => {
                    if (err) {
                        console.error('Error al obtener el cliente:', err);
                        res.status(500).send('Error en el servidor.');
                    } else if (clienteResult.length > 0) {
                        informe.cliente = clienteResult[0].nombre;
                        informe.clienteFoto = clienteResult[0].foto_base64; // Añadir la foto Base64

                        // Obtener el técnico relacionado con la foto
                        const tecnicoQuery = `
                            SELECT nombre, TO_BASE64(foto) AS foto_base64 
                            FROM usuarios_hidro 
                            WHERE id = ?
                        `;
                        db.query(tecnicoQuery, [informe.tecnico], (err, tecnicoResult) => {
                            if (err) {
                                console.error('Error al obtener el técnico:', err);
                                res.status(500).send('Error en el servidor.');
                            } else if (tecnicoResult.length > 0) {
                                informe.tecnico = tecnicoResult[0].nombre;
                                informe.tecnicoFoto = tecnicoResult[0].foto_base64; // Añadir la foto Base64 del técnico

                                obtenerListas((err, tecnicos, clientes) => {
                                    if (err) {
                                        res.status(500).send('Error en el servidor.');
                                    } else {
                                        // Renderizar la vista con el informe y las listas
                                        res.render('administrativo/informes/consulta_informe.hbs', {
                                            layout: 'layouts/nav_admin.hbs',
                                            nombreUsuario,
                                            informe,
                                            tecnicos,
                                            clientes
                                        });
                                    }
                                });
                            } else {
                                res.render('administrativo/informes/consulta_informe.hbs', {
                                    layout: 'layouts/nav_admin.hbs',
                                    nombreUsuario,
                                    mensajeError: 'No se encontró el técnico relacionado.'
                                });
                            }
                        });
                    } else {
                        res.render('administrativo/informes/consulta_informe.hbs', {
                            layout: 'layouts/nav_admin.hbs',
                            nombreUsuario,
                            mensajeError: 'No se encontró el cliente relacionado.'
                        });
                    }
                });
            } else {
                obtenerListas((err, tecnicos, clientes) => {
                    if (err) {
                        res.status(500).send('Error en el servidor.');
                    } else {
                        res.render('administrativo/informes/consulta_informe.hbs', {
                            layout: 'layouts/nav_admin.hbs',
                            nombreUsuario,
                            tecnicos,
                            clientes,
                            mensajeError: 'No se encontró ningún informe con el ID proporcionado.'
                        });
                    }
                });
            }
        });
    } else {
        res.redirect('/login');
    }
});

// Función para obtener listas de técnicos y clientes
function obtenerListas(callback) {
    const clientesQuery = 'SELECT id, nombre FROM clientes_hidrolubombas';
    db.query(clientesQuery, (err, clientes) => {
        if (err) {
            console.error('Error al obtener los clientes:', err);
            return callback(err);
        }

        const tecnicosQuery = `
            SELECT DISTINCT m.tecnico, u.nombre AS tecnico_name 
            FROM mantenimiento_hidro m
            LEFT JOIN usuarios_hidro u ON m.tecnico = u.id
        `;
        db.query(tecnicosQuery, (err, tecnicosResults) => {
            if (err) {
                console.error('Error al obtener los técnicos:', err);
                return callback(err);
            }

            const tecnicos = tecnicosResults.map(row => ({
                id: row.tecnico,
                name: row.tecnico_name
            }));
            callback(null, tecnicos, clientes);
        });
    });
}




app.get('/get_ids_mantenimiento', (req, res) => {
    const clienteId = req.query.cliente;
    console.log('Cliente seleccionado:', clienteId); // Verificar que el clienteId sea correcto

    const query = 'SELECT id FROM mantenimiento_hidro WHERE cliente = ?';
    db.query(query, [clienteId], (err, results) => {
        if (err) {
            console.error('Error al obtener los IDs de mantenimiento:', err);
            res.status(500).send('Error en el servidor');
        } else {
            console.log('IDs de mantenimiento:', results); // Verificar que los resultados sean correctos
            res.json(results);
        }
    });
});





app.get('/get_informe_ids', (req, res) => {
    const tecnico = req.query.tecnico;

    if (!tecnico) {
        return res.status(400).json({ error: 'Técnico no proporcionado' });
    }

    const query = 'SELECT id FROM mantenimiento_hidro WHERE tecnico = ?';
    db.query(query, [tecnico], (err, results) => {
        if (err) {
            console.error('Error al obtener los IDs del informe:', err);
            return res.status(500).json({ error: 'Error en el servidor' });
        }

        res.json(results); // Send back the list of IDs as JSON
    });
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





// Ruta para el menú administrativo - Mostrar formulario para nuevo usuario
app.get('/agregar_usuario', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario
        res.render('administrativo/usuarios/crear_usuarios.hbs', { nombreUsuario,layout: 'layouts/nav_admin.hbs', });
    } else {
        res.redirect('/login');
    }
});

app.post('/agregar_usuario', upload.single('foto'), async (req, res) => {
    const { nombre, email, password, role, firma } = req.body;
    const foto = req.file ? req.file : null;

    // Validar campos obligatorios
    if (!nombre || !email || !password || !role || !firma || !foto) {
        return res.status(400).send('Todos los campos son obligatorios.');
    }

    try {
        // Insertar usuario con foto (binario) y firma (cadena Base64)
        const query = `INSERT INTO usuarios_hidro (nombre, email, password, role, foto, firma) VALUES (?, ?, ?, ?, ?, ?)`;
        await pool.query(query, [nombre, email, password, role, foto.buffer, firma]);

        res.redirect('/menuAdministrativo');
    } catch (error) {
        console.error('Error al insertar el usuario:', error);
        res.status(500).send('Error al insertar el usuario.');
    }
});












app.post('/guardar_ubicacion', (req, res) => {
    const { tecnico, lat, lng } = req.body;

    // Obtener la hora local en la zona horaria adecuada
    const horaLocal = moment().tz("America/Bogota").format("YYYY-MM-DD HH:mm:ss");

    const query = 'INSERT INTO ubicaciones_tecnicos (tecnico, latitud, longitud, hora) VALUES (?, ?, ?, ?)';
    pool.query(query, [tecnico, lat, lng, horaLocal], (error, results) => {
        if (error) {
            console.error('Error al guardar la ubicación:', error);
            res.status(500).send('Error al guardar la ubicación');
        } else {
            res.json({ success: true, message: 'Ubicación guardada correctamente' });
        }
    });
});
  app.get('/obtener_ubicaciones_tecnicos', async (req, res) => {
    try {
      // Usar promesas para ejecutar la consulta
      const [results] = await pool.query('SELECT tecnico, latitud, longitud FROM ubicaciones_tecnicos ORDER BY timestamp DESC');
      res.json(results);  // Enviar las ubicaciones al frontend
    } catch (error) {
      console.error('Error al obtener las ubicaciones:', error);
      res.status(500).json({ error: 'Error al obtener las ubicaciones' });
    }
  });
  


// Ruta para el menú administrativo - Mostrar formulario para nuevo usuario
app.get('/agregar_clientes', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario
        res.render('administrativo/clientes/agregar_clientes.hbs', { nombreUsuario,layout: 'layouts/nav_admin.hbs', });
    } else {
        res.redirect('/login');
    }
});



                
// Ruta para guardar cliente
app.post('/guardar_cliente', upload.single('foto'), async (req, res) => {
    if (req.session.loggedin === true) {
        const { nombre, nit, correo, numero, direccion } = req.body;
        const foto = req.file ? req.file.buffer : null;

        try {
            const query = `INSERT INTO clientes_hidrolubombas (nombre, nit, correo, numero, direccion, foto, createdAt) 
                           VALUES (?, ?, ?, ?, ?, ?, NOW())`;
            const values = [nombre, nit, correo, numero, direccion, foto];
            
            await pool.query(query, values);

            res.redirect('/agregar_clientes'); // Redirige de vuelta al formulario o a otra página
        } catch (error) {
            console.error('Error al guardar cliente:', error);
            res.status(500).send('Hubo un error al guardar el cliente.');
        }
    } else {
        res.redirect('/login');
    }
});         




app.get('/consultar_clientes', async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const query = `
                SELECT id, nombre, nit, correo, numero, direccion, foto
                FROM clientes_hidrolubombas`;
            const [clientesRaw] = await pool.query(query);

            // Convertir las fotos de LONGBLOB a Base64
            const clientes = clientesRaw.map(cliente => {
                if (cliente.foto) {
                    cliente.fotoBase64 = `data:image/jpeg;base64,${cliente.foto.toString('base64')}`;
                } else {
                    cliente.fotoBase64 = '/path/to/placeholder.jpg'; // Imagen por defecto si no tiene foto
                }
                return cliente;
            });

            const nombreUsuario = req.session.user.name; // Datos del usuario
            res.render('administrativo/clientes/consultar_clientes.hbs', {
                nombreUsuario,
                clientes,
                layout: 'layouts/nav_admin.hbs',
            });
        } catch (error) {
            console.error('Error al consultar los clientes:', error);
            res.status(500).send('Hubo un error al recuperar los clientes.');
        }
    } else {
        res.redirect('/login');
    }
});



app.get('/buscar_clientes', async (req, res) => {
    try {
        const nombreFiltro = req.query.nombre || ''; // Filtro de búsqueda
        const query = `
            SELECT id, nombre, nit, correo, numero, direccion
            FROM clientes_hidrolubombas
            WHERE nombre LIKE ?`; // Coincidencias parciales
        const [clientes] = await pool.query(query, [`%${nombreFiltro}%`]);

        res.json({ clientes }); // Devuelve los resultados en formato JSON
    } catch (error) {
        console.error('Error al buscar clientes:', error);
        res.status(500).json({ error: 'Error al buscar clientes' });
    }
});



app.get('/eliminar_cliente/:id', async (req, res) => {
    const { id } = req.params; // ID del cliente a eliminar
    try {
        await pool.query('DELETE FROM clientes_hidrolubombas WHERE id = ?', [id]);
        res.redirect('/consultar_clientes'); // Redirige a la lista de clientes
    } catch (error) {
        console.error('Error al eliminar cliente:', error);
        res.status(500).send('Hubo un error al eliminar el cliente.');
    }
});









app.get('/editar_cliente/:id', async (req, res) => {
    const { id } = req.params; // ID del cliente a editar
    try {
        const [cliente] = await pool.query('SELECT * FROM clientes_hidrolubombas WHERE id = ?', [id]);
        if (cliente.length === 0) {
            return res.status(404).send('Cliente no encontrado.');
        }
        res.render('administrativo/clientes/editar_cliente.hbs', {
            cliente: cliente[0], // Enviar los datos al template
            layout: 'layouts/nav_admin.hbs',
        });
    } catch (error) {
        console.error('Error al cargar el cliente:', error);
        res.status(500).send('Hubo un error al cargar el cliente.');
    }
});


app.post('/editar_cliente/:id', upload.single('foto'), async (req, res) => {
    const { id } = req.params;
    const { nombre, nit, correo, numero, direccion } = req.body;

    console.log('Archivo recibido:', req.file); // Verifica si el archivo llega

    try {
        let query = `
            UPDATE clientes_hidrolubombas
            SET nombre = ?, nit = ?, correo = ?, numero = ?, direccion = ?
        `;
        const params = [nombre, nit, correo, numero, direccion];

        if (req.file) {
            console.log('Foto recibida, procesando...');
            query += `, foto = ?`;
            params.push(req.file.buffer); // Buffer de la foto
        }

        query += ` WHERE id = ?`;
        params.push(id);

        await pool.query(query, params);
        res.redirect('/consultar_clientes'); // Redirigir a la lista de clientes
    } catch (error) {
        console.error('Error al actualizar cliente:', error);
        res.status(500).send('Hubo un error al actualizar el cliente.');
    }
});


app.get('/api/clientes/:id', (req, res) => {
    const { id } = req.params;

    db.query('SELECT correo, foto FROM clientes_hidrolubombas WHERE id = ?', [id], (error, results) => {
        if (error) {
            console.error('Error al obtener los datos del cliente:', error);
            return res.status(500).json({ success: false, message: 'Error del servidor' });
        }

        if (results.length > 0) {
            const { correo, foto } = results[0];
            const fotoBase64 = foto ? `data:image/jpeg;base64,${foto.toString('base64')}` : null;
            res.json({ success: true, correo, foto: fotoBase64 });
        } else {
            res.status(404).json({ success: false, message: 'Cliente no encontrado' });
        }
    });
});




app.get('/api/tecnicos/:id', async (req, res) => {
    const tecnicoId = req.params.id;

    try {
        // Consulta la foto del técnico en la base de datos
        const [rows] = await pool.query(
            'SELECT foto FROM usuarios_hidro WHERE id = ?',
            [tecnicoId]
        );

        if (rows.length > 0 && rows[0].foto) {
            const fotoBuffer = rows[0].foto;
            res.setHeader('Content-Type', 'image/jpeg'); // Cambiar según el tipo de imagen
            res.send(fotoBuffer);
        } else {
            res.status(404).send('Foto no encontrada');
        }
    } catch (error) {
        console.error('Error al obtener la foto:', error);
        res.status(500).send('Error del servidor');
    }

});





app.get('/api/tecnico/firma/:id', async (req, res) => {
    const tecnicoId = req.params.id;
    try {
        const query = 'SELECT firma FROM usuarios_hidro WHERE id = ?';
        const [rows] = await pool.query(query, [tecnicoId]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Técnico no encontrado' });
        }

        // Verificar si firma es un Buffer y convertirla a string
        const firma = rows[0].firma instanceof Buffer ? rows[0].firma.toString('utf8') : rows[0].firma;

        // Agregar prefijo base64 si no está presente
        const firmaBase64 = firma.startsWith('data:image/png;base64,')
            ? firma
            : `data:image/png;base64,${firma}`;

        res.json({ firma: firmaBase64 });
    } catch (error) {
        console.error('Error al obtener la firma:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});






app.get('/Consulta_informes_realizados', async (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario

        try {
            // Consulta para obtener los datos con el tipo de mantenimiento incluido
            const [results] = await pool.query(`
                SELECT 
                    mh.id, 
                    mh.fecha, 
                    ch.nombre AS cliente, 
                    uh.nombre AS tecnico,  -- Obtiene el nombre del técnico
                    mh.equipo, 
                    mh.tipo_de_mantenimiento -- Asegúrate de que este campo existe en la tabla mantenimiento_hidro
                FROM 
                    mantenimiento_hidro mh
                JOIN 
                    clientes_hidrolubombas ch 
                ON 
                    mh.cliente = ch.id
                JOIN 
                    usuarios_hidro uh 
                ON 
                    mh.tecnico = uh.id -- Relaciona la tabla con el ID del técnico
            `);

            // Renderiza la vista con los datos obtenidos
            res.render('administrativo/informes/consulta_mejorada.hbs', {
                nombreUsuario,
                layout: 'layouts/nav_admin.hbs',
                datos: results, // Pasa los datos obtenidos a la vista
            });
        } catch (error) {
            console.error('Error al ejecutar la consulta:', error);
            return res.status(500).send('Error al cargar los informes.');
        }
    } else {
        res.redirect('/login');
    }
});








app.get('/mostrarInforme/:id', async (req, res) => {
    const id = req.params.id;

    try {
        // Consultar los datos del informe en la tabla mantenimiento_hidro
        const [result] = await pool.query('SELECT * FROM mantenimiento_hidro WHERE id = ?', [id]);

        if (result.length === 0) {
            return res.status(404).send('No se encontraron datos para el ID especificado.');
        }

        const informe = result[0]; // Obtener el informe

        // Convertir la firma del supervisor a Base64 si existe
        if (informe.firma_supervisor) {
            informe.firma_supervisor = Buffer.from(informe.firma_supervisor).toString('base64');
        } else {
            informe.firma_supervisor = null; // Si no hay firma, asignar 
        }

        // Consultar la foto, nombre y firma del técnico en la tabla usuarios_hidro
        const [tecnicoResult] = await pool.query(
            'SELECT nombre, foto, firma FROM usuarios_hidro WHERE id = ?', [informe.tecnico]
        );
        if (tecnicoResult.length > 0) {
            const tecnicoData = tecnicoResult[0];
            informe.tecnicoNombre = tecnicoData.nombre; // Asignar el nombre del técnico
            if (tecnicoData.foto) {
                informe.tecnicoFoto = Buffer.from(tecnicoData.foto).toString('base64'); // Convertir foto a Base64
            } else {
                informe.tecnicoFoto = null; // Si no hay foto, asignar null
            }
            if (tecnicoData.firma) {
                informe.firma_tecnico = tecnicoData.firma; // La firma ya está en formato Base64
            } else {
                informe.firma_tecnico = null; // Si no hay firma, asignar null
            }
        } else {
            informe.tecnicoNombre = 'Técnico no encontrado'; // Si no se encuentra, asignar un mensaje predeterminado
            informe.tecnicoFoto = null;
            informe.firma_tecnico = null;
        }

        // Consultar la foto y el nombre del cliente en la tabla clientes_hidrolubombas
        const [clienteResult] = await pool.query(
            'SELECT nombre, foto FROM clientes_hidrolubombas WHERE id = ?', [informe.cliente]
        );
        if (clienteResult.length > 0) {
            const clienteData = clienteResult[0];
            informe.clienteNombre = clienteData.nombre; // Asignar el nombre del cliente
            if (clienteData.foto) {
                informe.clienteFoto = Buffer.from(clienteData.foto).toString('base64'); // Convertir foto a Base64
            } else {
                informe.clienteFoto = null; // Si no hay foto, asignar null
            }
        } else {
            informe.clienteNombre = 'Cliente no encontrado'; // Si no se encuentra, asignar un mensaje predeterminado
            informe.clienteFoto = null;
        }

        // Renderizar la plantilla con los datos
        res.render('administrativo/informes/plantilla.hbs', { informe , layout: 'layouts/nav_admin.hbs'});
    } catch (error) {
        console.error('Error al generar el informe:', error);
        res.status(500).send('Error interno del servidor.');
    }
});



hbs.registerHelper('not', function(value) {
    return !value;
});












app.get('/editarMantenimiento/:id', async (req, res) => {
    const mantenimientoId = req.params.id;
    try {
        // Obtener datos del mantenimiento
        const queryMantenimiento = 'SELECT * FROM mantenimiento_hidro WHERE id = ?';
        const [rows] = await pool.query(queryMantenimiento, [mantenimientoId]);

        if (rows.length === 0) {
            return res.status(404).send('Mantenimiento no encontrado');
        }

        // Obtener el ID del cliente desde el mantenimiento
        const clienteId = rows[0].cliente;

        // Consulta para obtener la lista de clientes
        const clientsQuery = 'SELECT id, nombre FROM clientes_hidrolubombas';
        const [clientes] = await pool.query(clientsQuery);

        // Encontrar el cliente correspondiente al ID
        const selectedCliente = clientes.find(client => client.id === parseInt(clienteId)) || null;

        // Imprimir en consola el ID y nombre del cliente, y lo que se está comparando
        console.log('ID del cliente en mantenimiento:', clienteId);
        if (selectedCliente) {
            console.log('Cliente encontrado:', selectedCliente);
        } else {
            console.log('Cliente no encontrado');
        }

        // Convertir la firma del supervisor a Base64 si existe
        if (rows[0].firma_supervisor) {
            rows[0].firma_supervisor = Buffer.from(rows[0].firma_supervisor).toString('base64');
        } else {
            rows[0].firma_supervisor = null; // Si no hay firma, asignar null
        }

        // Obtener el ID del técnico desde el mantenimiento
        const tecnicoId = rows[0].tecnico; // ID del técnico

        // Obtener lista de técnicos
        const tecnicosQuery = `SELECT id, nombre FROM usuarios_hidro WHERE role = "tecnico"`;
        const [tecnicos] = await pool.query(tecnicosQuery);

        // Encontrar el técnico correcto en la lista de técnicos
        const selectedTecnico = tecnicos.find(tec => tec.id === parseInt(tecnicoId)) || null;

        // Comparar el técnico encontrado con el nombre del técnico en el mantenimiento
        const tecnicoSeleccionadoNombre = selectedTecnico ? selectedTecnico.nombre : 'Ninguno';

        // Imprimir en consola el ID y nombre del técnico
        console.log('ID del técnico en mantenimiento:', tecnicoId);
        console.log('Técnico encontrado:', tecnicoSeleccionadoNombre);

        // Enviar datos a la vista
        res.render('administrativo/informes/editar.hbs', {
            informe: rows[0],
            clientes,
            selectedClienteId: selectedCliente ? selectedCliente.id : null, // ID del cliente seleccionado
            selectedClienteNombre: selectedCliente ? selectedCliente.nombre : '', // Nombre del cliente seleccionado
            tecnicos, // Lista completa de técnicos
            selectedTecnicoId: selectedTecnico ? selectedTecnico.id : null, // Solo el ID del técnico
            layout: 'layouts/nav_admin.hbs'
        });
    } catch (error) {
        console.error('Error al obtener la firma:', error);
        res.status(500).json({ error: 'Error del servidor' });
    }
});













const fs = require('fs');






app.post('/actualizar-informe', async (req, res) => {
    try {
        // Extraer todos los campos del formulario
        const {
            id,
            cliente, equipo, tecnico, torre, hora_entrada, hora_salida, fecha, numero,
            variador_b1, variador_b2, variador_b3, variador_b4, precarga,
            guarda_motor_b11, guarda_motor_b22, guarda_motor_b33, guarda_motor_b44,
            mutelillas_b1, mutelillas_b2, mutelillas_b3, mutelillas_b4, flotador_mecanico,
            breaker_b1, breaker_b2, breaker_b3, breaker_b4, piloto_b1, piloto_b2,
            piloto_b3, piloto_b4, valvulas_succion,
            contactores_b1, contactores_b2, contactores_b3, contactores_b4, tanque_hidro,
            presostatos_b1, presostatos_b2, presostatos_b3, presostatos_b4, cheques,
            flotador_electricos_b1, flotador_electricos_b2, flotador_electricos_b3, flotador_electricos_b4,
            alternador_b1, alternador_b2, alternador_b3, alternador_b4, presion_linea,
            conexiones_b11, conexiones_b22, conexiones_b33, conexiones_b44,
            guarda_motor_b1, guarda_motor_b2, guarda_motor_b3, guarda_motor_b4, registros,
            amperaje_b11, amperaje_b22, amperaje_b33, amperaje_b44,
            temporizador_b1, temporizador_b2, temporizador_b3, temporizador_b4, membrana,
            voltaje_b11, voltaje_b22, voltaje_b33, voltaje_b44,
            rele_termico_b1, rele_termico_b2, rele_termico_b3, rele_termico_b4, manometro,
            sierena_b1, sierena_b2, sierena_b3, sierena_b4,
            flotador_electrico_b1, flotador_electrico_b2, flotador_electrico_b3, flotador_electrico_b4,
            cargador_aire, conexiones_b1, conexiones_b2, conexiones_b3, conexiones_b4, tanque_reserva,
            residuos_b1, residuos_b2, residuos_b3, residuos_b4, amperaje_b1, amperaje_b2, amperaje_b3, amperaje_b4,
            flauta_descarga, voltaje_b1, voltaje_b2, voltaje_b3, voltaje_b4,
            rodamientos_m1, rodamientos_m2, rodamientos_m3, rodamientos_m4,
            impulsor_m1, impulsor_m2, impulsor_m3, impulsor_m4, cambio, falla, pendiente, diagnostico,
            verificado, operando, casquillo_b1, casquillo_b2, casquillo_b3, casquillo_b4,
            sello_mecanico_b1, sello_mecanico_b2, sello_mecanico_b3, sello_mecanico_b4,
            empaque_b1, empaque_b2, empaque_b3, empaque_b4, empaque_2_b1, empaque_2_b2, empaque_2_b3, empaque_2_b4,
            ventilador_b1, ventilador_b2, ventilador_b3, ventilador_b4,
            carcasa_b1, carcasa_b2, carcasa_b3, carcasa_b4, bornes_b1, bornes_b2, bornes_b3, bornes_b4,
            casquillo_b11, casquillo_b22, casquillo_b33, casquillo_b44,
            bobinado_b1, bobinado_b2, bobinado_b3, bobinado_b4, partes_para_cambio, observaciones,
            firma_supervisor, tipo_de_mantenimiento, Correo
        } = req.body;

        console.log("Firma Supervisor:", firma_supervisor); // Esto te permitirá ver si la firma se está recibiendo correctamente

        if (!id || isNaN(parseInt(id))) {
            return res.status(400).json({ error: "El ID es requerido y debe ser un número válido." });
        }

        // Crear un objeto 'updates' para almacenar los valores que se actualizarán
        let updates = {};
        Object.entries(req.body).forEach(([key, value]) => {
            if (value !== null && value !== undefined) {
                updates[key] = value;
            }
        });
        // Si hay una firma, convertirla de base64 a un buffer binario
    
// Si hay una firma nueva, convertirla de base64 a un buffer binario
if (req.body.firma_supervisor) {
    updates.firma_supervisor = Buffer.from(req.body.firma_supervisor, 'base64');
}
        let setClauses = [];
        let values = [];

     // Construir las cláusulas SET de la consulta
for (const key in updates) {
    setClauses.push(`${key} = ?`);
    values.push(updates[key]);
}

        if (setClauses.length === 0) {
            return res.status(400).json({ error: "No se recibieron datos para actualizar además del ID." });
        }

        // Agregar el ID al final de los valores
        const query = `UPDATE mantenimiento_hidro SET ${setClauses.join(', ')} WHERE id = ?`;
        values.push(id);

        // Ejecutar la consulta
        const [result] = await pool.query(query, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "No se encontró ningún informe con ese ID." });
        }

      
        // Enviar URL de redirección al cliente
        res.json({ redirectUrl: `/mostrarInforme/${id}` });

    } catch (err) {
        console.error("Error en la actualización:", err);
        res.status(500).json({ error: "Hubo un error al actualizar el informe." });
    }
});








// Establecemos el límite de tamaño de la carga
const maxSize = 50 * 1024 * 1024; // 50MB

app.post('/enviar-correoo', (req, res) => {
    const { correo, imagen } = req.body;

    if (!correo || !imagen) {
        return res.status(400).json({ success: false, message: 'Faltan parámetros' });
    }

    // Configurar el transporter de nodemailer
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'ingeoperativos@gmail.com',
            pass: 'gwkdpbzedomryivi', // Asegúrate de usar una forma segura de almacenar las credenciales
        },
    });

    const mailOptions = {
        from: 'ingeoperativos@gmail.com',
        to: correo,
        subject: 'Reenvío de reporte',
        text: 'Aquí está el reporte solicitado.',
        attachments: [
            {
                filename: 'captura.png',
                content: imagen.split('base64,')[1], // Decodificar la imagen de Base64
                encoding: 'base64', // Indicar que el contenido es base64
            },
        ],
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error al enviar correo:', error);
            return res.status(500).json({ success: false, message: 'Error al enviar el correo.' });
        }

        console.log('Correo enviado:', info.response);
        res.json({ success: true, message: 'Correo reenviado exitosamente.' });
    });
});


// Iniciar el servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});