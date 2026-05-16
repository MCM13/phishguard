import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Configuración de Vite con el plugin oficial de React.
// El servidor de desarrollo se expone en 0.0.0.0:3000 para que sea
// accesible desde el host cuando se ejecuta dentro de Docker.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
  },
});
