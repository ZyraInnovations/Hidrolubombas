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














// Ruta para el menú administrativo - Mostrar formulario para nuevo usuario
app.get('/realizar_informe', (req, res) => {
    if (req.session.loggedin === true) {
        const nombreUsuario = req.session.user.name; // Usa los datos de la sesión del usuario
        res.render('administrativo/informes/crear_informe.hbs', { nombreUsuario });
    } else {
        res.redirect('/login');
    }
});














// Iniciar el servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});