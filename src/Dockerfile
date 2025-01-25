# Usa una imagen base de Node.js
FROM node:18

# Configura el directorio de trabajo en el contenedor
WORKDIR /app

# Copia los archivos package.json y package-lock.json al contenedor
COPY package*.json ./

# Instala las dependencias
RUN npm install

# Copia el resto de los archivos de tu proyecto
COPY . .

# Cambia al directorio donde está el app.js
WORKDIR /app/src

# Expone el puerto 3000
EXPOSE 3000

# Comando para iniciar la aplicación
CMD ["node", "app.js"]
