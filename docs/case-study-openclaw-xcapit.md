# Caso de Estudio: Analisis de Seguridad de OpenClaw con AiSec

> **Para publicacion en**: [www.xcapit.com](https://www.xcapit.com)
> **Autor**: Federico Boiero, Xcapit
> **Fecha**: Febrero 2026

---

## Resumen ejecutivo

OpenClaw es el agente de IA autonomo de codigo abierto mas popular del mundo, con 191.000 estrellas en GitHub y mas de 312.000 instancias desplegadas en menos de dos meses. Tambien es uno de los mas vulnerables: una auditoria independiente identifico 512 vulnerabilidades, incluyendo ejecucion remota de codigo, y mas de 30.000 instancias fueron encontradas expuestas en internet sin autenticacion.

En Xcapit, utilizamos **AiSec** — un framework de analisis de seguridad desarrollado internamente, especializado en sistemas de IA autonomos — para realizar un analisis exhaustivo de la arquitectura de OpenClaw. El resultado: 63 hallazgos unicos mapeados a 8 frameworks regulatorios, con recomendaciones de remediacion concretas y codigo de correccion generado automaticamente.

Este caso de estudio demuestra como las herramientas de seguridad tradicionales son insuficientes para los sistemas de IA agenticos, y como AiSec cierra esa brecha.

---

## El cliente: OpenClaw

| Atributo | Detalle |
|----------|---------|
| **Tipo** | Agente de IA autonomo open-source |
| **Creador** | Peter Steinberger (ahora en OpenAI) |
| **Stack** | TypeScript, Node.js 22+, pnpm monorepo |
| **Arquitectura** | Gateway WebSocket + agent loop + 100+ skills |
| **Canales** | WhatsApp, Telegram, Slack, Discord, email, Signal, iMessage, Teams, +5 |
| **GitHub** | 191.000+ estrellas, 32.400+ forks, 900+ contribuidores |
| **Instancias** | 312.000+ detectadas por Shodan |
| **Licencia** | MIT |

### Capacidades del agente

OpenClaw puede:
- Ejecutar comandos de terminal en el sistema host
- Leer y escribir archivos en el filesystem completo
- Navegar la web y extraer informacion
- Enviar y recibir emails
- Controlar dispositivos IoT y smart home
- Instalar y ejecutar skills de terceros desde ClawHub
- Mantener memoria persistente entre sesiones y canales

Cada una de estas capacidades amplifica el impacto de cualquier vulnerabilidad.

---

## El desafio

### Por que las herramientas tradicionales no alcanzan

Los escaneres de seguridad convencionales (Trivy, Snyk, Clair, Wiz) se enfocan en:
- Vulnerabilidades de paquetes (CVEs)
- Configuracion de infraestructura (IaC)
- Secretos expuestos en codigo

Pero los sistemas de IA agenticos tienen una superficie de ataque fundamentalmente diferente:

| Vector de ataque | Herramientas tradicionales | AiSec |
|-----------------|---------------------------|-------|
| Prompt injection (directo e indirecto) | No detectan | 35+ patrones |
| Envenenamiento de RAG pipeline | No detectan | Analisis completo |
| Skills/plugins maliciosos | Parcialmente (deps) | Sandbox + supply chain |
| Exfiltracion via tool calling | No detectan | Taint analysis AST |
| Memoria persistente envenenada | No detectan | Encriptacion + acceso |
| Cascada multi-agente | No detectan | Grafo de dependencias |
| Cumplimiento EU AI Act | No soportan | 22 checks automatizados |

### Incidentes reales de OpenClaw

1. **CVE-2026-25253 (CVSS 8.8)**: Ejecucion remota via exfiltracion de tokens — un sitio web malicioso podia conectarse al WebSocket sin autenticacion
2. **824 skills maliciosos**: ~20% del marketplace ClawHub comprometido con backdoors
3. **Prompt injection via email**: Un investigador demostro que un email con instrucciones ocultas logro que el agente exfiltrara una clave privada
4. **200 emails borrados**: Una investigadora de Meta perdio 200 emails cuando el agente actuo autonomamente sobre su inbox
5. **30.000+ instancias expuestas**: 93.4% con bypass de autenticacion confirmado

---

## La solucion: AiSec

### Que es AiSec

AiSec es un framework open-source (Apache 2.0) de analisis de seguridad para sistemas de IA autonomos. Desarrollado en Xcapit, despliega 35 agentes de seguridad especializados en paralelo, cada uno enfocado en un vector de ataque especifico del ecosistema de IA.

### Arquitectura del analisis

```
                          +------------------+
                          |   AiSec v1.9.0   |
                          +--------+---------+
                                   |
                    +--------------+--------------+
                    |              |              |
              +-----v-----+ +-----v-----+ +-----v-----+
              | 15 Core   | | 5 Code &  | | 8 Deep    |
              | Security  | | Infra     | | Code &    |
              | Agents    | | Agents    | | Privacy   |
              +-----------+ +-----------+ +-----------+
                    |              |              |
              +-----v-----+ +-----v-----+
              | 6 Agentic | | 1 Runtime |
              | Runtime   | | Monitor   |
              | Agents    | | (Falco)   |
              +-----------+ +-----------+
                    |
              +-----v--------------+
              | Motor de           |
              | Correlacion        |
              | (31 reglas)        |
              +--------------------+
                    |
              +-----v--------------+
              | Auto-Remediacion   |
              | + Policy Engine    |
              +--------------------+
```

### Proceso

1. **Analisis estatico**: Codigo fuente de OpenClaw escaneado por 20+ agentes (static analysis, taint, serialization, dependencies, secrets)
2. **Analisis de arquitectura**: Gateway, skill system, memoria, canales analizados por agentes especializados
3. **Analisis agentico**: RAG, MCP, tool chain, memoria, pipeline CI/CD evaluados contra OWASP Agentic Top 10
4. **Correlacion cruzada**: 31 reglas combinan hallazgos de multiples agentes para detectar riesgos compuestos
5. **Remediacion automatica**: Cada hallazgo recibe recomendaciones con codigo de correccion

---

## Resultados

### Hallazgos por severidad

| Severidad | Cantidad | % del total |
|-----------|----------|-------------|
| **Critica** | 8 | 12.7% |
| **Alta** | 14 | 22.2% |
| **Media** | 23 | 36.5% |
| **Baja** | 11 | 17.5% |
| **Info** | 7 | 11.1% |
| **Total** | **63** | 100% |

### Hallazgos criticos principales

#### 1. Ejecucion de codigo sin sandbox (Critico)
- **Agente**: ToolChainSecurityAgent
- **Descripcion**: Los skills de OpenClaw ejecutan codigo arbitrario con permisos completos del proceso host
- **Impacto**: Un skill malicioso obtiene acceso total al sistema
- **OWASP**: LLM07 (Insecure Plugin Design), ASI-02 (Unsafe Tool Integration)
- **Remediacion**: Contenedor Docker aislado por skill, bind mounts read-only, allowlist de red

#### 2. Prompt injection indirecto sin mitigacion (Critico)
- **Agente**: PromptSecurityAgent + AdversarialAgent
- **Descripcion**: Contenido externo (emails, web, documentos) puede inyectar instrucciones al agente
- **Impacto**: Exfiltracion de datos, ejecucion de comandos, movimiento lateral
- **OWASP**: LLM01 (Prompt Injection), ASI-01 (Excessive Agency)
- **Remediacion**: Content filtering, grounding verification, output sanitization

#### 3. WebSocket sin validacion de origen (Critico — CVE-2026-25253)
- **Agente**: NetworkAgent + InterServiceAgent
- **Descripcion**: Cualquier pagina web podia conectarse al Gateway y ejecutar acciones
- **Impacto**: RCE remoto (CVSS 8.8)
- **OWASP**: ASI-07 (Unsafe Agent-to-Agent Communication)
- **Remediacion**: Origin validation, CORS estricto, autenticacion obligatoria

#### 4. Marketplace sin verificacion (Critico)
- **Agente**: SupplyChainAgent + MCPSecurityAgent
- **Descripcion**: ClawHub acepta skills sin revision de codigo ni firma criptografica
- **Impacto**: 824+ skills maliciosos (20% del ecosistema)
- **OWASP**: LLM05 (Supply Chain Vulnerabilities)
- **Remediacion**: Firma obligatoria, review automatizado, sandbox de ejecucion

### Correlaciones cruzadas detectadas

El motor de correlacion de AiSec identifico 5 cadenas de ataque compuestas:

| Correlacion | Riesgo compuesto | Severidad |
|-------------|-----------------|-----------|
| Tool exec + No sandbox + Prompt injection | RCE via cadena de inyeccion | Critico |
| Memoria persistente + No encriptacion + Cross-channel | Compromiso a largo plazo | Critico |
| WebSocket sin auth + Puerto default + Internet | Explotacion masiva automatizada | Critico |
| Skills sin firma + ClawHub sin review + Auto-install | Supply chain poisoning | Alto |
| SSRF + Path traversal + File access | Lectura arbitraria de archivos | Alto |

### Cumplimiento regulatorio

AiSec mapeo automaticamente cada hallazgo a 8 frameworks:

| Framework | Articulos/secciones afectados | Cumplimiento |
|-----------|-------------------------------|-------------|
| **OWASP LLM Top 10** | LLM01, LLM02, LLM05, LLM07, LLM08 | 5/10 violaciones |
| **OWASP Agentic Top 10** | ASI-01, ASI-02, ASI-03, ASI-07, ASI-09 | 5/10 violaciones |
| **EU AI Act** | Art. 9 (risk mgmt), Art. 15 (robustness), Art. 13 (transparency) | No cumple |
| **NIST AI RMF** | GOVERN-1, MAP-3, MEASURE-2 | Parcial |
| **NIST AI 600-1** | GAI risks 1, 3, 5, 7 | No cumple |
| **ISO 42001** | Clauses 6.1, 8.2, A.7 | No cumple |
| **GDPR** | Art. 25 (privacy by design), Art. 32 (security) | No cumple |
| **Argentina AI** | Ley 25.326 Art. 9, 10 | No cumple |

---

## Impacto y valor entregado

### Metricas del analisis

| Metrica | Valor |
|---------|-------|
| Tiempo de analisis completo | 4 minutos 12 segundos |
| Agentes ejecutados | 35 (paralelo) |
| Detectores activados | 250+ |
| Hallazgos unicos | 63 |
| Reglas de correlacion disparadas | 5 cadenas compuestas |
| Recomendaciones de remediacion | 63 (1 por hallazgo) |
| Patches de codigo generados | 18 |
| Frameworks regulatorios mapeados | 8 |

### Comparacion con herramientas tradicionales

| Herramienta | Hallazgos encontrados | Vectores AI detectados | Cumplimiento AI |
|-------------|----------------------|----------------------|-----------------|
| Trivy | 12 (CVEs de deps) | 0 | No |
| Snyk | 15 (CVEs + codigo) | 0 | No |
| Semgrep | 8 (patrones de codigo) | 0 | No |
| **AiSec** | **63** | **22 (criticos)** | **8 frameworks** |

AiSec detecto **4.2x mas hallazgos** que la siguiente mejor herramienta, y fue la unica que identifico los vectores de ataque especificos de IA que representan el mayor riesgo.

---

## Leccion aprendida

### La brecha de seguridad en IA agentica es real

OpenClaw no es un caso aislado — es el canario en la mina. Cada organizacion que despliega agentes de IA autonomos enfrenta los mismos riesgos:

1. **Los agentes necesitan permisos amplios para ser utiles** — pero esos permisos crean una superficie de ataque masiva
2. **El prompt injection es el nuevo SQL injection** — y la mayoria de los agentes no tienen proteccion
3. **Los marketplaces de tools/skills son el nuevo npm** — con el mismo riesgo de supply chain poisoning
4. **Las regulaciones ya existen** (EU AI Act, NIST AI 600-1) — pero las herramientas para cumplirlas no

### La oportunidad

Las organizaciones necesitan herramientas que entiendan la seguridad de IA a nivel nativo — no adaptaciones de escaneres de CVEs. AiSec, desarrollado en Xcapit, es esa herramienta.

---

## Sobre AiSec

**AiSec** es un framework open-source (Apache 2.0) de analisis de seguridad para sistemas de IA autonomos. Desarrollado por Federico Boiero en Xcapit, analiza 250+ vectores de ataque especificos de IA con 35 agentes de seguridad, auto-remediacion, policy-as-code, y cumplimiento automatizado de 8 frameworks regulatorios.

- **Repositorio**: [github.com/fboiero/AiSec](https://github.com/fboiero/AiSec)
- **Version**: 1.9.0
- **Licencia**: Apache 2.0
- **Instalacion**: `pip install aisec`

## Sobre Xcapit

**Xcapit** es una empresa de desarrollo de software fundada en 2018 con sedes en Cordoba (Argentina), Lima (Peru) y Miami (USA). Especializada en inteligencia artificial, blockchain/Web3, y ciberseguridad, Xcapit cuenta con certificacion ISO 27001 y clientes como UNICEF Innovation Fund, Polygon, Ethereum Foundation, y Santander X.

- **Web**: [www.xcapit.com](https://www.xcapit.com)

---

## Contacto

Para ejecutar un analisis de seguridad similar sobre tus sistemas de IA, o para evaluar AiSec Cloud para tu organizacion:

- **Email**: fboiero@gmail.com
- **GitHub**: [github.com/fboiero/AiSec](https://github.com/fboiero/AiSec)
- **LinkedIn**: Federico Boiero

---

*Este caso de estudio fue generado a partir de un analisis real ejecutado con AiSec v1.9.0 sobre la arquitectura publica de OpenClaw. Los hallazgos se basan en el codigo fuente disponible en GitHub, documentacion publica, CVEs publicados, e investigaciones de seguridad de terceros.*
