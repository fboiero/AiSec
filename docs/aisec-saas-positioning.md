# AiSec SaaS — Plataforma de Seguridad para Sistemas de IA Autonomos

> Documento de posicionamiento estrategico — Febrero 2026

---

## Vision

**AiSec Cloud** es la primera plataforma SaaS de seguridad disenada exclusivamente para sistemas de IA autonomos. Mientras las herramientas tradicionales (Snyk, Trivy, Wiz, Prisma Cloud) se enfocan en vulnerabilidades de infraestructura y codigo, AiSec analiza los vectores de ataque unicos de agentes de IA: prompt injection, envenenamiento de RAG, explotacion de MCP, hijacking de tool chains, fuga de embeddings, fallas en cascada multi-agente, y mas.

---

## El problema de mercado

### La explosion de agentes de IA autonomos

- **OpenClaw**: 191.000 estrellas en GitHub, 312.000+ instancias desplegadas en semanas
- **Mercado de agentes de IA**: Proyectado a $65B para 2028 (McKinsey)
- **Cada empresa Fortune 500** esta evaluando o desplegando agentes internos
- **Frameworks agenticos** (LangChain, CrewAI, AutoGPT, LlamaIndex) crecen 300% anual

### El gap de seguridad

- **Las herramientas existentes no entienden IA**: Trivy encuentra CVEs de paquetes, no prompt injection
- **Los pentesters no escalan**: Un pentest manual de un agente toma semanas y cuesta $50-100K
- **Las regulaciones se endurecen**: EU AI Act (vigente), NIST AI 600-1 (vigente), ISO 42001 (adoptandose)
- **Los incidentes crecen exponencialmente**: Solo OpenClaw tuvo 512 vulnerabilidades, 30K instancias expuestas, 824 skills maliciosos en un mes

### El caso OpenClaw como catalizador

OpenClaw demostro al mundo que los agentes de IA autonomos son un vector de ataque masivo. Cada CISO ahora pregunta: "Nuestros agentes internos, estan seguros?" La respuesta es: no lo saben, porque no tienen herramientas para medirlo.

---

## La solucion: AiSec Cloud

### Producto core

Una plataforma SaaS que ejecuta analisis de seguridad continuo sobre sistemas de IA autonomos:

```
Desarrollador/DevSecOps → Conecta agente/imagen → AiSec ejecuta 35 agentes de seguridad
→ Dashboard con hallazgos → Auto-remediacion con patches → Policy gate en CI/CD
→ Monitoreo runtime continuo → Reportes de cumplimiento automaticos
```

### Tiers

| Plan | Precio | Incluye |
|------|--------|---------|
| **Community** | Gratis | CLI open-source, 35 agentes, reportes locales, 1 escaneo/dia |
| **Team** | $499/mes | 10 proyectos, dashboard web, API, 50 escaneos/dia, historico 90 dias, 3 usuarios |
| **Business** | $1.999/mes | Proyectos ilimitados, escaneos ilimitados, SSO/SAML, webhooks, politicas custom, runtime monitoring, cumplimiento automatizado, 10 usuarios |
| **Enterprise** | Custom | On-premise/VPC, SLA 99.9%, soporte dedicado, integraciones custom, auditorias trimestrales, usuarios ilimitados |

### Diferenciadores clave

| Capacidad | AiSec | Snyk | Trivy | Wiz |
|-----------|-------|------|-------|-----|
| Prompt injection detection | 35+ patrones | No | No | No |
| RAG pipeline security | Si | No | No | No |
| MCP server hardening | Si | No | No | No |
| Tool chain sandboxing audit | Si | No | No | No |
| Agent memory security | Si | No | No | No |
| Multi-agent cascade analysis | Si | No | No | No |
| OWASP LLM Top 10 | Completo | Parcial | No | No |
| OWASP Agentic Top 10 | Completo | No | No | No |
| EU AI Act compliance | 22 checks | No | No | No |
| Auto-remediacion con codigo | Si | Si | No | Si (IaC) |
| Runtime monitoring (eBPF) | Si | No | No | Si |
| AI-CVSS scoring | Si | No | No | No |

### Integraciones

- **CI/CD**: GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI
- **Cloud**: AWS, GCP, Azure (reportes a S3/GCS/Blob)
- **Contenedores**: Docker, Kubernetes, Helm
- **Monitoreo**: Prometheus, Grafana, PagerDuty, OpsGenie
- **Comunicacion**: Slack, Teams, Discord (notificaciones)
- **Compliance**: SARIF (GitHub Code Scanning), PDF/HTML reportes

---

## Go-to-Market

### Fase 1 — Community & Awareness (Q1 2026) ← ESTAMOS ACA

**Objetivo**: Establecer AiSec como el estandar open-source de seguridad para IA.

- **Open-source momentum**: 35 agentes, 1.453 tests, 8 frameworks de cumplimiento
- **Content marketing**: Blog post de OpenClaw como caso de estudio (viral potential)
- **Developer relations**: Documentacion, quickstart, plugin development guide
- **GitHub Action**: `uses: fboiero/AiSec@v1` — zero friction adoption
- **Partnerships**: Xcapit como primer caso de uso enterprise

### Fase 2 — SaaS Beta (Q2 2026)

**Objetivo**: Lanzar AiSec Cloud con early adopters.

- **Infraestructura**: Multi-tenant en AWS/GCP con Kubernetes
- **Dashboard web**: Ya construido (v1.6), migrar a multi-tenant
- **API**: Ya construida (v1.0+), agregar autenticacion por org
- **Onboarding**: `aisec cloud connect` CLI command
- **Pricing**: Free tier + Team ($499) para beta
- **Target**: 50 equipos beta, 500 escaneos/semana

### Fase 3 — General Availability (Q3 2026)

**Objetivo**: Lanzamiento publico con todos los tiers.

- **Enterprise features**: SSO/SAML, audit log, role-based access, VPC deployment
- **Marketplace**: Plugin marketplace para agentes custom
- **Compliance certifications**: SOC 2 Type II, ISO 27001 (aprovechando Xcapit)
- **Channel partnerships**: Consultoras de seguridad, MSSPs

### Fase 4 — Scale (Q4 2026+)

**Objetivo**: Escalar a 1.000+ clientes.

- **Runtime agent**: Lightweight sidecar que monitorea agentes de IA en produccion 24/7
- **AI Security Posture Management (AI-SPM)**: Vista unificada de todos los agentes de IA en la organizacion
- **Threat intelligence**: Feed de skills maliciosos, patrones de ataque, IoCs
- **Acquisitions**: Herramientas complementarias (fuzzing, model security)

---

## Mercado objetivo

### Segmento primario: Empresas con agentes de IA en produccion

- **Perfil**: Equipos de 50-500 ingenieros, 5-50 agentes de IA desplegados
- **Pain point**: "No sabemos si nuestros agentes son seguros, y la regulacion nos exige demostrarlo"
- **Decision maker**: CISO / VP Engineering / Head of AI
- **Budget**: $50K-200K/anio en herramientas de seguridad

### Segmento secundario: Startups de IA

- **Perfil**: 5-50 ingenieros, construyendo productos basados en agentes
- **Pain point**: "Necesitamos pasar auditorias de seguridad para cerrar enterprise deals"
- **Decision maker**: CTO / CEO
- **Budget**: $5K-50K/anio

### Segmento terciario: Consultoras de seguridad

- **Perfil**: Firmas de pentest y seguridad que necesitan tooling para IA
- **Pain point**: "Nuestros clientes nos piden pentests de sus agentes de IA y no tenemos herramientas"
- **Decision maker**: Managing Partner / Practice Lead
- **Budget**: License + revenue share

---

## Modelo de negocio

### Revenue streams

1. **SaaS subscriptions** (80%) — Recurrente mensual/anual
2. **Professional services** (15%) — Implementacion, integracion custom, capacitacion
3. **Marketplace fees** (5%) — Comision sobre plugins/agentes premium

### Unit economics objetivo (Q4 2026)

| Metrica | Target |
|---------|--------|
| ARR | $2M |
| Clientes pagos | 200 |
| ARPU | $10K/anio |
| Churn mensual | <3% |
| CAC | <$5K |
| LTV/CAC | >5x |
| Gross margin | >80% |

### Funding

- **Pre-seed**: Bootstrapped (open-source + Xcapit revenue)
- **Seed** (Q2 2026): $1-2M para infraestructura SaaS, equipo de 5, y go-to-market
- **Series A** (Q1 2027): $8-15M para escalar, enterprise sales team, SOC 2

---

## Ventaja competitiva sostenible

1. **First mover en AI agent security**: No existe otra herramienta que cubra los 10 vectores agenticos
2. **Open-source core**: Comunidad de desarrolladores contribuyendo agentes, detecciones, y frameworks
3. **Data moat**: Cada escaneo enriquece nuestros patrones de deteccion (anonimizado)
4. **Compliance depth**: 8 frameworks mapeados con trazabilidad articulo-por-articulo
5. **Ecosystem lock-in**: Policy-as-code en CI/CD, dashboard integrado, runtime monitoring — dificil de reemplazar una vez adoptado
6. **Xcapit backing**: ISO 27001, clientes enterprise (UNICEF, Polygon, Santander), credibilidad en seguridad

---

## Equipo necesario (Seed)

| Rol | Responsabilidad |
|-----|-----------------|
| **CEO/CTO** (Federico Boiero) | Vision, arquitectura, producto |
| **Backend Engineer** | Multi-tenancy, API, infra |
| **Frontend Engineer** | Dashboard SaaS, onboarding |
| **Security Researcher** | Nuevos agentes, detecciones, research |
| **DevRel / Marketing** | Content, community, partnerships |

---

## Metricas de traccion actual

| Metrica | Valor |
|---------|-------|
| Version | 1.9.0 |
| Agentes de seguridad | 35 |
| Reglas de correlacion | 31 |
| Tests | 1.453 |
| Lineas de codigo | ~38.700 |
| Frameworks de cumplimiento | 8 |
| Estrategias de remediacion | 16+ |
| Opciones de deploy | 10 (CLI, API, Docker, K8s, Helm, GH Action, etc.) |
| Releases en 9 dias | 11 (v0.1 → v1.9) |

---

*Documento preparado por Federico Boiero — Febrero 2026*
*Confidencial — Para uso interno y potenciales inversores*
