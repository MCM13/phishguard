# Prompt para Lovable — Rediseño UI PhishGuard

Copia y pega el bloque siguiente en Lovable (o similar).

---

## PROMPT

Rediseña la interfaz de **PhishGuard**, una herramienta web de análisis de phishing con IA. Stack actual: **React 18 + Vite + Tailwind CSS + React Router**. Backend FastAPI ya existente — **no cambies la lógica de API**, solo la UI/UX.

### Contexto del producto
- El usuario pega una **URL** o un **email** sospechoso.
- La API devuelve: `score` (0-100), `verdict` (PHISHING | SOSPECHOSO | LEGÍTIMO), `indicators[]`, `ai_explanation`, `virustotal_detections`, `virustotal_available`, `virustotal_total_engines`, `timestamp`.
- Endpoints: `POST /api/analyze/url`, `POST /api/analyze/email`, `GET /api/history`, `GET /api/stats`.
- Variable de entorno: `VITE_API_URL` para la base del API.

### Estética deseada (impresionar, dinámico, ciberseguridad premium)
- **Tema oscuro** tipo SOC / cyber dashboard: fondo `#020617` (slate-950).
- **Fondo animado sutil**: mesh gradient con orbes difuminados (cyan `#0ea5e9`, violeta `#6366f1`, rojo tenue `#ef4444` al 5% opacidad), grid técnico animado muy suave, sin distraer.
- **Glassmorphism**: tarjetas con `backdrop-blur`, bordes `border-white/10`, sombras con glow del color del veredicto.
- **Tipografía**: Inter o **Plus Jakarta Sans** / **Space Grotesk** para títulos.
- **Hero impactante** en Dashboard: título con gradiente animado (sky → cyan), subtítulo, 3-4 badges (Claude IA, VirusTotal, URLScan, Heurísticas).
- **Micro-interacciones**: hover en stats (elevación + borde brillante), tabs con slide indicator, botón primario con shine/shimmer al hover, inputs con glow al focus.
- **Score gauge**: semicírculo SVG animado (stroke-dashoffset transition), pulso suave si score > 60.
- **ResultCard**: borde y glow según veredicto — rojo PHISHING, ámbar SOSPECHOSO, verde LEGÍTIMO. URLs PHISHING **nunca clicables** (solo texto + badge [bloqueado]).
- **Loading**: skeleton con shimmer, no spinners genéricos solos.
- **Historial**: tabla moderna con pills de veredicto, filas con hover, paginación clara.

### Páginas
1. **/** Dashboard — stats desde `/api/stats` (total_analyzed, phishing_detected, detection_rate, avg_score, anthropic_quota), tabs URL/Email, formularios, ResultCard.
2. **/history** — listado paginado, filtro por veredicto.

### Restricciones técnicas
- **No** `dangerouslySetInnerHTML`.
- Errores con mensajes genéricos en español (sin stack traces).
- Enlaces externos: `rel="noopener noreferrer"`.
- Responsive mobile-first.
- Mantener español en toda la UI.
- Componentes: `URLAnalyzer`, `EmailAnalyzer`, `ResultCard`, `ScoreGauge`, `IndicatorList`, `HistoryTable`.
- Código limpio, sin librerías pesadas innecesarias; preferir CSS/Tailwind. Framer Motion opcional solo si aporta mucho.

### Paleta
- Brand accent: sky-400 / cyan-500
- PHISHING: red-500
- SOSPECHOSO: amber-500
- LEGÍTIMO: emerald-500
- Texto: slate-100 / slate-400

### Entregable
UI completa que se sienta como producto SaaS de ciberseguridad de 2025, no plantilla genérica. Navbar sticky con blur, favicon escudo azul, sensación de “centro de operaciones” al analizar amenazas.

---
