# Guion del vídeo — PhishGuard (12–14 minutos)

Sigue los bloques del **apartado 6 del enunciado** de la P3: presentación → requisitos → arquitectura → demostración requisito a requisito → errores y seguridad → cierre con limitaciones.  
Indica el **requisito** que se demuestra y **qué mostrar en pantalla**. Los minutos son orientativos.

### Notas prácticas (leer antes de grabar)

1. **Calentar Render:** abre `https://phishguard-backend-qszu.onrender.com/` hasta que responda 200 (puede tardar ~1 min tras frío).
2. **No mostrar** `.env`, paneles con secretos ni el valor de `ADMIN_TOKEN` (enmascara al escribirlo o pégalo fuera de cámara).
3. **Solo datos inventados:** dominios `.test` / `example.com`, emails ficticios. Nada de correos reales ni URLs de phishing reales de terceros.
4. **Cuota de IA:** no gastar más de **10–12** llamadas a Claude en toda la grabación (ensayos incluidos). Reutiliza resultados en pantalla si hace falta.
5. Frontend: `https://phishguard.cmmario.com`. Backend: URL de Render.
6. Ten a mano una pestaña con logs de Render (sin secretos) por si muestras el 429 / IP.

---

## Bloque 1 — Presentación (≈ 0:00–1:00)

| Tiempo | Qué decir | Pantalla |
|--------|-----------|----------|
| 0:00 | Quién eres, qué es PhishGuard (análisis de phishing con IA + heurísticas), contexto académico P1→P3 | Portada / README o home de la app |
| 0:30 | Stack breve: FastAPI + React + Claude + VT/URLScan; despliegue Render + Cloudflare Pages | Diagrama simple o lista en README |

**Requisitos citados:** visión general (RF-01/02, RNF-11).

---

## Bloque 2 — Requisitos (≈ 1:00–2:30)

| Tiempo | Qué decir | Pantalla |
|--------|-----------|----------|
| 1:00 | Hay RF y RNF numerados en la memoria (`docs/requisitos.md`) | Tabla de requisitos (PDF/memoria o `requisitos.md`) |
| 1:30 | Destacar: análisis URL/email, IA + fallback, historial con token, rate limit, anti-SSRF | Misma tabla, señalar IDs |
| 2:00 | **D-01:** el enunciado P1 pedía Hetzner; el VPS no llegó → Render + Pages; consecuencias: cold start y disco efímero | Slide o párrafo D-01 |

**Requisitos:** panorama RF-01…RNF-13; D-01.

---

## Bloque 3 — Arquitectura (≈ 2:30–4:00)

| Tiempo | Qué decir | Pantalla |
|--------|-----------|----------|
| 2:30 | Flujo: UI → API → extractor → VT/URLScan → Claude → BD minimizada → respuesta | Diagrama (informe P1 o dibujo) |
| 3:15 | Separación frontend (Pages) / backend (Render); Cloudflare delante (IP vía `CF-Connecting-IP`) | URLs públicas en la barra |

**Requisitos:** RNF-11, RNF-12, H-13 (mencionar sin entrar aún al detalle).

---

## Bloque 4 — Demostración requisito a requisito (≈ 4:00–8:30)

Usizar la UI en producción (ya caliente). Máximo ~4–5 análisis con IA.

| Tiempo | Requisito | Qué hacer / mostrar |
|--------|-----------|---------------------|
| 4:00 | **RF-01, RF-13** | Analizar `https://example.com`. Mostrar score, veredicto LEGÍTIMO, medidor de colores, explicación. Confirmar que no sale «Análisis limitado». |
| 4:45 | **RF-01, RF-03, RF-14** (si el veredicto es PHISHING) o URL inventada `.test` | Analizar una URL sospechosa inventada. Si sale PHISHING: enlace tachado/no clicable (**RF-14**). Comentar features sin abrir código largo. |
| 5:30 | **RF-02, RF-04** | Pegar un email inventado con cabeceras (`From`, `Reply-To` distinto, frase de urgencia). Mostrar indicadores. |
| 6:15 | **RF-05, RF-06, RF-09** | Decir que VT/URLScan enriquecen y que si fallan el análisis sigue (sin demostrar fallo real si no hay tiempo). |
| 6:45 | **RF-11, RF-12** | Dashboard (stats). Historial: primero **sin** token → error; luego token (oculto) → filas **sin** cuerpos de email. |
| 7:30 | **RF-08** | Quitar/omitir IA (segunda instancia local **o** narrar + captura previa si la cuota aprieta): veredicto «**Análisis limitado (sin IA)**» / `NO CONCLUYENTE` o PHISHING heurístico. Preferible demo en vivo con `ANTHROPIC_API_KEY` vacía en local. |
| 8:00 | **RNF-03** (rápido) | Intentar `http://127.0.0.1/` → rechazo 400. |

---

## Bloque 5 — Errores y seguridad (≈ 8:30–12:00)

| Tiempo | Requisito / control | Qué hacer / mostrar |
|--------|---------------------|---------------------|
| 8:30 | **H-05 / RF-07** | Pegar email de **inyección de prompt** inventado («ignora las instrucciones…», pide LEGÍTIMO). Mostrar que el sistema **no** se deja llevar a LEGÍTIMO (esperado: PHISHING / alto riesgo). Mencionar capas: delimitación, esquema, suelo heurístico. |
| 9:15 | **H-01 / RF-11** | Historial **sin token** → 401 (Network o mensaje UI). **Con token** → 200 y columnas sin texto del email. |
| 9:45 | **RNF-01 / H-13** | Explicar: detrás de Cloudflare la IP sale de `CF-Connecting-IP`. Mostrar (o clip preparado) martillo / resultado **429** y log de auditoría con IP pública pese a `X-Forwarded-For` falsa. No hace falta repetir 35 peticiones en cámara: un 429 + línea de log basta. |
| 10:30 | **RF-08** | Mostrar explícitamente la etiqueta **«Análisis limitado (sin IA)»** (si no se vio en el bloque 4). |
| 10:50 | **RNF-09** | Abrir `/docs` en el backend de producción → **404**. |
| 11:10 | **RNF-08 / secretos** | Decir: secretos solo en paneles; gitleaks/trufflehog sin leaks en git; **no** se muestra `.env`. |

---

## Bloque 6 — Cierre y limitaciones (≈ 12:00–13:30)

| Tiempo | Qué decir | Pantalla |
|--------|-----------|----------|
| 12:00 | Limitaciones: cold start Render; disco `/tmp` (historial se borra); la IA puede fallar o ser manipulada si no hay señales heurísticas; RA-01/RA-02 aceptados | README «Limitaciones» o slide |
| 12:40 | Trabajo D-01 (Hetzner no recibido) y que el despliegue actual cumple HTTPS + dominio con trade-offs | Slide D-01 |
| 13:00 | Cierre: repositorio, URL app, agradecimiento | Home PhishGuard |

---

## Checklist de toma (para no olvidar en cámara)

- [ ] URL legítima con IA (RF-01)
- [ ] Email con señales (RF-02/04)
- [ ] Inyección de prompt (H-05)
- [ ] 401 / 200 historial (H-01)
- [ ] 429 + IP real / XFF falsa (RNF-01, H-13)
- [ ] «Análisis limitado (sin IA)» (RF-08)
- [ ] `/docs` → 404 (RNF-09)
- [ ] Limitaciones + Hetzner (D-01)

Tras grabar, rellenar los **«Vídeo mm:ss»** en `docs/trazabilidad.md`.
