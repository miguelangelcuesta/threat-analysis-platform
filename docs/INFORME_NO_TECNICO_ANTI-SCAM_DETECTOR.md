# Informe para personas no técnicas — Anti-Scam Detector

> Este documento explica el proyecto de forma clara y “para hablar con cualquier persona”.

---

## 1) ¿Qué es Anti-Scam Detector?
Anti-Scam Detector es una aplicación que **ayuda a detectar señales de phishing y posibles fraudes** en:
- **Mensajes (texto)** que alguien te podría enviar.
- **Enlaces (URLs)** que vienen dentro de esos mensajes.

La herramienta no “decide” con certeza si algo es una estafa: ofrece una **evaluación orientativa** basada en patrones. Sirve como **capa extra de seguridad** para que puedas actuar con más cautela.

---

## 2) ¿Qué problema resuelve?
Muchas estafas intentan que la víctima:
- haga clic en un enlace,
- inicie sesión en una página falsa,
- entregue datos (contraseñas, códigos, información bancaria),
- o actúe por presión (“urgente”, “última oportunidad”).

Este proyecto intenta detectar esas señales de forma automática.

---

## 3) ¿Cómo funciona a nivel general (de usuario a motor)?
Cuando tú analizas un mensaje o enlace, ocurre este flujo:

1. **La interfaz (frontend)** te deja pegar el texto o la URL.
2. **La aplicación (backend)** recibe tu solicitud vía API.
3. **El motor de análisis** calcula un **nivel de riesgo** con dos tipos de información:
   - lo que el mensaje “parece” por su lenguaje (análisis semántico),
   - y lo que el enlace/dominio “sugiere” por reglas prácticas (análisis de dominio).
4. **Se devuelve el resultado** a la pantalla, con semáforo, resumen y señales.

---

## 4) ¿Qué analiza el sistema?

### A) Análisis semántico (lo que dice el texto)
El motor compara el texto con “ejemplos internos” de patrones típicos de estafa, como:
- intención de **suplantación** (hacerte creer que es un servicio real),
- intentos de **robo de credenciales** (p. ej. “verifica tu cuenta”, “introduce tu contraseña”, etc.),
- mensajes con **urgencia/manipulación** (“ahora mismo”, “última advertencia”),
- y otros indicios frecuentes.

En lenguaje simple: el sistema busca si el mensaje se parece a los tipos de intentos más comunes.

### B) Análisis de URL y dominio (lo que implica el enlace)
El motor extrae el dominio de las URLs y le aplica reglas como:
- ¿El dominio intenta **parecerse a marcas conocidas** (suplantación)?
- ¿El dominio contiene **palabras típicas** de phishing (como login/verify/secure/account)?
- ¿El dominio tiene una forma **inusual** (por ejemplo, muy largo)?

Además, cuando es posible, intenta estimar riesgo con información de antigüedad del dominio (WHOIS). Si esa parte falla, el sistema no penaliza por un error técnico.

---

## 5) ¿Cómo se calcula el “riesgo” (explicado fácil)?
El motor crea un número de riesgo entre **0 y 100** combinando:
- señales del análisis del **texto** (semántico),
- señales del análisis del **enlace/dominio**,
- y señales adicionales del dominio (como antigüedad cuando está disponible).

Después convierte el número en un semáforo:
- **safe (verde)**: bajo riesgo
- **suspicious (amarillo)**: riesgo moderado (hay señales que revisar)
- **danger (rojo)**: alto riesgo (mejor no interactuar)

---

## 6) ¿Qué muestra la aplicación en pantalla?

1. **Semáforo visual (Traffic Light)**:
   - verde / amarillo / rojo según el resultado.

2. **Acción recomendada**, en lenguaje claro:
   - **Rojo**: “Bloquear inmediatamente”
   - **Amarillo**: “Revisar antes de interactuar”
   - **Verde**: “Sin acción necesaria”

3. **Señales detectadas** (explicadas en español), por ejemplo:
   - “Suplantación de marca”
   - “Posible robo de credenciales”
   - “Palabras típicas de phishing”
   - “Dominio recién creado / reciente / inusualmente largo”

4. **Resumen**: un texto breve con el motivo general del veredicto.

---

## 7) Limitaciones (esto es importante)
- Es una herramienta **orientativa**, basada en patrones: puede equivocarse.
- Puede haber **falsos positivos** (algo parece malicioso, pero no lo es).
- Puede haber **falsos negativos** (una estafa sofisticada puede no encajar en patrones).
- La parte de “reputación/antigüedad” del dominio puede no estar disponible en algunos entornos.

Recomendación práctica: úsalo para **decidir con más cautela**, no como “veredicto absoluto”.

---

## 8) Guion corto para explicarlo a cualquier persona

> “Anti-Scam Detector ayuda a detectar phishing o mensajes engañosos. Analiza el texto por su lenguaje (si usa tácticas típicas) y también revisa el enlace por señales del dominio. Con todo eso calcula un nivel de riesgo y lo muestra como semáforo. No es infalible, pero sirve como una capa extra para decidir si hay que bloquear o revisar antes de interactuar.”

---

## 9) Resumen en una frase
Anti-Scam Detector es un analizador automático que compara texto y enlaces con señales conocidas de phishing y fraude para darte una alerta accionable.

