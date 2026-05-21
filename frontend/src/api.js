import axios from 'axios';

// La URL del backend se inyecta en build/dev mediante la variable
// de entorno VITE_API_URL. Por defecto apuntamos a localhost:8000.
const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL,
  timeout: 60_000,
  headers: { 'Content-Type': 'application/json' },
});

// Servicio que centraliza las llamadas a los endpoints del backend
export const analyzeUrl = async (url) => {
  const { data } = await api.post('/api/analyze/url', { url });
  return data;
};

export const analyzeEmail = async (content) => {
  const { data } = await api.post('/api/analyze/email', { content });
  return data;
};

export const getHistory = async ({ page = 1, pageSize = 20, verdict = null } = {}) => {
  const params = { page, page_size: pageSize };
  if (verdict) params.verdict = verdict;
  const { data } = await api.get('/api/history', { params });
  return data;
};

export const getStats = async () => {
  const { data } = await api.get('/api/stats');
  return data;
};

/**
 * Convierte cualquier error de axios en un mensaje amigable en español.
 *
 * No expone trazas, clases de excepción ni detalles internos al usuario.
 * Sólo en errores 400 reutiliza el `detail` que envía el backend, ya que
 * esos mensajes son validaciones del propio input del usuario.
 */
export const friendlyError = (err) => {
  if (!err) return 'Ha ocurrido un error inesperado. Inténtalo de nuevo.';

  if (err.response) {
    const { status, data } = err.response;
    const detail = data?.detail;

    switch (status) {
      case 400:
        return typeof detail === 'string'
          ? detail
          : 'La información enviada no es válida.';
      case 413:
        return 'El contenido enviado es demasiado grande.';
      case 415:
        return 'Formato de petición no admitido.';
      case 429:
        return (
          typeof detail === 'string'
            ? detail
            : 'Has hecho demasiadas peticiones. Espera un momento antes de volver a intentarlo.'
        );
      case 504:
        return 'El servidor tardó demasiado en responder. Inténtalo de nuevo.';
      default:
        if (status >= 500) {
          return 'Se ha producido un error en el servidor. Inténtalo de nuevo más tarde.';
        }
        return 'No se pudo completar la operación.';
    }
  }

  if (err.request) {
    return 'No se puede contactar con el servidor. Comprueba tu conexión.';
  }

  return 'Ha ocurrido un error inesperado.';
};

export default api;
