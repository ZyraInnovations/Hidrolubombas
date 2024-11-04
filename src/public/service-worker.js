// Instalación del Service Worker y cacheo de recursos
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open('app-cache').then(function(cache) {
            return cache.addAll([
                '/login', // Página principal
                '/login', // Ruta del login que carga la vista Handlebars
                '/styles.css', // Archivo CSS
                '/app.js', // Archivo JavaScript principal
                '/manifest.json', // Manifesto de la aplicación
                'imagenes/logo%20ingenieria.jpeg.jpg' // Asegúrate de que el espacio esté codificado correctamente
            ]);
        }).then(() => self.skipWaiting()) // Hace que el nuevo Service Worker tome el control inmediatamente
    );
});

// Interceptar solicitudes y responder desde el cache si es posible
self.addEventListener('fetch', function(event) {
    event.respondWith(
        caches.match(event.request).then(function(response) {
            return response || fetch(event.request);
        })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        new Promise(resolve => setTimeout(resolve, 1000)) // Retraso de 1 segundo
        .then(() => caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    return caches.delete(cacheName);
                })
            );
        })).then(() => self.clients.claim())
    );
});
