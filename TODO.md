# TODO anti-scam-detector (correcciones)

## Backend
- [x] Corregir import frágil en `backend/server.py` (import relativo desde paquete).
- [x] Corregir lógica `domain_risk()` en `backend/analysis_engine.py` para evaluar “dominio legítimo” de forma consistente.
- [x] Hacer `whois_risk()` robusto al tipo de `creation_date` (normalizar a `datetime`).


## Frontend
- [x] Unificar llamadas a la API: hacer que `DashboardPage.js` use `frontend/src/api/client.js`.
- [x] Confirmar que `REACT_APP_BACKEND_URL` está usado correctamente (y evitar hardcodeo).

## Verificación
- [ ] Ejecutar compile/check y (si aplica) levantar backend/frontend para validar flujo completo.

