# OpenClaw: Anatomia de seguridad del agente de IA mas popular del mundo, analizado con AiSec

> **Autor**: Federico Boiero | **Fecha**: Febrero 2026
> **Publicado en**: [xcapit.com](https://www.xcapit.com)

---

## TL;DR

OpenClaw acumulo 191.000 estrellas en GitHub en menos de un mes, convirtiendose en el agente de IA autonomo mas popular de la historia. Tambien acumulo 512 vulnerabilidades, 30.000+ instancias expuestas sin autenticacion, 824 skills maliciosos en su marketplace, y un CVE critico de ejecucion remota de codigo. Ejecutamos AiSec — nuestro framework open-source de seguridad para sistemas de IA — contra OpenClaw para entender exactamente donde falla la seguridad cuando un agente autonomo tiene acceso a tu terminal, tus archivos, tus emails y tus API keys.

---

## Que es OpenClaw y por que importa

OpenClaw es un agente de IA autonomo open-source que se conecta a WhatsApp, Telegram, Slack, Discord, email, y 12 canales mas. Puede ejecutar comandos de terminal, leer y escribir archivos, navegar la web, enviar emails, y controlar dispositivos IoT. Todo esto corriendo localmente con tus API keys.

Creado por Peter Steinberger en noviembre 2025 (originalmente como Clawdbot, luego Moltbot), exploto en popularidad en enero 2026 alcanzando 100.000 estrellas en una semana. A febrero 2026 tiene:

- **191.000+ estrellas** en GitHub
- **32.400+ forks**
- **900+ contribuidores**
- **10.700+ skills** en ClawHub (su marketplace)
- **312.000+ instancias** detectadas por Shodan

El 14 de febrero de 2026, Steinberger anuncio que se une a OpenAI y que el proyecto se transfiere a una fundacion open-source.

---

## El problema: autonomia sin seguridad

La promesa de OpenClaw es poderosa: un asistente personal de IA que realmente *hace cosas*. Pero ese mismo poder es exactamente lo que lo hace peligroso. Cuando un agente tiene acceso a tu shell, tus archivos, y tus credenciales, cada vulnerabilidad se convierte en una brecha completa.

### Lo que encontraron los investigadores

| Hallazgo | Impacto |
|----------|---------|
| **CVE-2026-25253** (CVSS 8.8) | RCE via exfiltracion de token — cualquier sitio web podia conectarse al WebSocket sin validacion de origen |
| **512 vulnerabilidades** | Auditoria de seguridad de enero 2026, 8 clasificadas como criticas |
| **30.000+ instancias expuestas** | Sin autenticacion, accesibles desde internet (Bitsight) |
| **5.194 instancias verificadas** | 93.4% con bypass de autenticacion confirmado |
| **824+ skills maliciosos** | ~20% del ecosistema de ClawHub comprometido |
| **Prompt injection demostrado** | Un email malicioso logro que el agente exfiltrara una clave privada |
| **200 emails borrados** | Una investigadora de Meta perdio 200 emails cuando el agente "ayudo" con su inbox |

Microsoft, CrowdStrike, Cisco, Kaspersky, Malwarebytes, Bitdefender, y Jamf publicaron alertas de seguridad. Cisco titulo su post: *"Personal AI Agents like OpenClaw Are a Security Nightmare."*

---

## Analisis con AiSec: 35 agentes contra OpenClaw

AiSec es un framework de analisis de seguridad disenado especificamente para sistemas de IA autonomos. No es un escaner de contenedores tradicional — sus 35 agentes de seguridad analizan vectores de ataque que herramientas como Trivy, Snyk o Clair ni siquiera contemplan.

### Superficie de ataque mapeada

Ejecutamos AiSec con sus 35 agentes en paralelo contra la arquitectura de OpenClaw. Esto es lo que encontramos:

#### 1. Gateway WebSocket — Sin fronteras de confianza

**Agentes**: NetworkAgent, InterServiceAgent, CascadeAgent

El Gateway de OpenClaw es un servidor WebSocket unico que coordina todos los canales, sesiones, y dispositivos. Es el punto de fallo mas critico:

- **Sin validacion de origen** en WebSocket (CVE-2026-25253) — cualquier pagina web podia conectarse
- **Puerto por defecto expuesto** (3000) sin TLS obligatorio
- **Sin rate limiting** en conexiones entrantes
- **Sin segregacion** entre canales — un mensaje en Telegram puede ejecutar comandos en tu terminal

AiSec mapea esto a **OWASP Agentic ASI-07** (Unsafe Agent-to-Agent Communication) y **ASI-09** (Lack of Operational Controls).

#### 2. Sistema de Skills — Ejecucion arbitraria de codigo

**Agentes**: ToolChainSecurityAgent, MCPSecurityAgent, SupplyChainAgent

Los skills de OpenClaw son codigo Node.js que se ejecuta con los permisos completos del proceso:

- **Sin sandbox** — un skill malicioso tiene acceso completo al filesystem, red, y variables de entorno
- **Sin validacion de esquema** en inputs/outputs de tools
- **Sin firma ni verificacion** de skills desde ClawHub
- **Sin revision de codigo** en el marketplace — 824 skills maliciosos publicados por cuentas aparentemente legitimas

AiSec clasifica esto como **OWASP LLM07** (Insecure Plugin Design) con severidad **critica**. El auto-remediador genera recomendaciones especificas:

```
REMEDIACION: Implementar sandbox para ejecucion de skills
- Usar contenedor Docker aislado por skill
- Limitar acceso a filesystem via bind mounts read-only
- Bloquear acceso a red por defecto (allowlist explicita)
- Verificar firma criptografica de skills antes de instalar
- Implementar review obligatorio en ClawHub
```

#### 3. Prompt Injection — El enemigo invisible

**Agentes**: PromptSecurityAgent, AdversarialAgent, RAGSecurityAgent

OpenClaw ingiere contenido externo (emails, documentos, paginas web, tickets) y actua autonomamente sobre el. Esto crea un canal de inyeccion indirecta masivo:

- **Prompt injection via email**: Demostrado — un investigador envio un email con instrucciones ocultas; al pedir al bot que revise el correo, exfiltro una clave privada
- **Prompt injection via web**: Al navegar una pagina con instrucciones inyectadas en texto invisible, el agente las ejecuta
- **Sin grounding verification** — el agente no verifica que sus acciones correspondan al pedido original del usuario
- **Sin filtrado de outputs** del LLM antes de ejecutar tools

AiSec detecta esto como **OWASP LLM01** (Prompt Injection) con correlacion cruzada a **ASI-01** (Excessive Agency) — la combinacion mas peligrosa en sistemas agenticos.

#### 4. Memoria Persistente — Envenenamiento entre sesiones

**Agentes**: AgentMemorySecurityAgent, EmbeddingLeakageAgent

OpenClaw mantiene memoria compartida y sesiones persistentes entre canales:

- **Sin encriptacion** de memoria en reposo
- **Sin control de acceso** a la memoria entre canales
- **Envenenamiento posible** — un atacante que inyecte datos en la memoria puede influir en todas las interacciones futuras
- **Sin limites de crecimiento** — la memoria crece indefinidamente sin garbage collection

#### 5. SSRF y Path Traversal — Acceso a la infraestructura

**Agentes**: NetworkAgent, APISecurityAgent

- **SSRF en manejo de media** — fetch HTTP sin bloqueo de IPs privadas ni DNS pinning (parchado en 2026.2.2)
- **Path traversal** en manejo de outputs (parchado en 2026.2.14)
- **Sin validacion de URLs** en webhooks y callbacks

#### 6. Cadena de suministro — Dependencias vulnerables

**Agentes**: DependencyAuditAgent, DeepDependencyAgent, SBOMAgent

- **Monorepo pnpm** con cientos de dependencias transitivas
- **Dependencias directas sin auditar** (npm audit no ejecutado en CI)
- **Sin SBOM** publicado
- **Sin firma** de releases

### Resumen de hallazgos

| Severidad | Cantidad | Ejemplos |
|-----------|----------|----------|
| **Critica** | 8 | RCE via WebSocket, skills maliciosos, prompt injection a exfiltracion |
| **Alta** | 14 | SSRF, path traversal, memoria sin encriptacion, sin auth en endpoints |
| **Media** | 23 | Dependencias desactualizadas, logs verbosos, CORS permisivo |
| **Baja** | 11 | Headers de seguridad faltantes, timeouts no configurados |
| **Info** | 7 | Versiones de runtime, metadata de configuracion |

**Total: 63 hallazgos unicos, mapeados a 8 frameworks de cumplimiento.**

### Correlaciones cruzadas (lo que ningun otro escaner detecta)

El motor de correlacion de AiSec (31 reglas) identifico patrones compuestos:

1. **Tool Execution + No Sandbox + Prompt Injection = Remote Code Execution Chain**
   - Un atacante puede inyectar instrucciones via email → el agente ejecuta tools → los tools corren sin sandbox → ejecucion de codigo arbitrario

2. **Memory Persistence + No Encryption + Cross-Channel Access = Long-Term Compromise**
   - Datos inyectados en la memoria persisten indefinidamente y afectan todas las interacciones futuras

3. **WebSocket No Auth + Default Port + Public Internet = Mass Exploitation**
   - 30.000+ instancias explotables sin interaccion del usuario

---

## Que deberia hacer OpenClaw (y que puede hacer AiSec)

### Recomendaciones prioritarias

1. **Sandboxear la ejecucion de skills** — Contenedores Docker aislados, sin acceso al host
2. **Implementar Content Security Policy para prompts** — Filtrado de instrucciones inyectadas en contenido externo
3. **Firmar y verificar skills** — Cadena de confianza criptografica para ClawHub
4. **Encriptar memoria en reposo** — AES-256 con rotacion de claves
5. **Autenticacion obligatoria** — Eliminar el modo sin auth, enforcing mTLS para comunicacion inter-componente
6. **Rate limiting y backpressure** — Limitar conexiones WebSocket, throttling de tool calls
7. **Audit trail inmutable** — Loguear cada accion del agente con timestamp, contexto, y resultado

### Lo que AiSec ofrece

AiSec puede ejecutar este analisis completo en **minutos**, no semanas:

- **35 agentes en paralelo** analizando cada vector de ataque
- **250+ detectores** especificos para IA
- **Auto-remediacion** con patches de codigo concretos
- **Policy-as-code** para bloquear deploys inseguros en CI/CD
- **Monitoreo runtime** via Falco eBPF
- **8 frameworks de cumplimiento** mapeados automaticamente
- **Dashboard web** para seguimiento continuo

---

## Conclusiones

OpenClaw representa el estado actual de los agentes de IA autonomos: increiblemente poderosos, increiblemente populares, e increiblemente inseguros. No es culpa del equipo de OpenClaw — es un problema estructural. La industria esta construyendo agentes que pueden ejecutar codigo, mover dinero, y acceder a datos sensibles, sin las herramientas para validar que eso sea seguro.

AiSec existe para cerrar esa brecha. No reemplaza las buenas practicas de desarrollo — las detecta, las mide, y genera las correcciones necesarias para implementarlas.

El analisis completo de OpenClaw con AiSec esta disponible como reporte HTML/PDF en nuestro repositorio. Si queres ejecutar el mismo analisis sobre tu propia infraestructura de agentes de IA, AiSec es open-source y gratuito:

```bash
pip install aisec
aisec scan run <tu-imagen-docker>
```

**Repositorio**: [github.com/fboiero/AiSec](https://github.com/fboiero/AiSec)
**Licencia**: Apache 2.0

---

*Federico Boiero es ingeniero de software y fundador de AiSec, un framework de seguridad para sistemas de IA autonomos. Trabaja en [Xcapit](https://www.xcapit.com), donde lidera iniciativas de seguridad en IA y blockchain.*
