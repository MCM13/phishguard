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

export default api;
