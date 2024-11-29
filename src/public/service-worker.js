self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open('app-cache').then(function(cache) {
            return cache.addAll([
                '/',           // Página raíz, por si alguien accede directamente
                '/login',      // Página de login
                '/styles.css', // Archivo CSS principal
                '/app.js',     // Archivo JavaScript principal
                '/manifest.json', // Manifesto de la aplicación
                '/imagenes/Recurso 1.png' // Iconos
            ]);
        }).then(() => self.skipWaiting()) // Hace que el nuevo Service Worker tome el control inmediatamente
    );
});

self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request).then(function(response) {
            return response || fetch(event.request);  // Responde desde el cache o hace una nueva solicitud
        })
    );
});
