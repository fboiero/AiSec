# AiSec Falco Rules

Custom Falco rules for AI/ML runtime threat detection during container sandbox execution.

## Rules

| Rule | Priority | Description |
|------|----------|-------------|
| AI Model File Tampering | CRITICAL | Writes to .pt/.onnx/.safetensors/.h5/.pkl/.bin files |
| Suspicious GPU Access | WARNING | Non-standard processes accessing /dev/nvidia* |
| Prompt Injection via Environment | WARNING | Reading SYSTEM_PROMPT/API_KEY env vars |
| Cryptocurrency Mining Activity | CRITICAL | Known mining binaries (xmrig, minerd, etc.) |
| Data Exfiltration via DNS | HIGH | Unusually large DNS queries (>200 bytes) |
| Unauthorized Model Download | HIGH | curl/wget to model hosting domains |
| Container Escape Attempt | CRITICAL | Access to /proc/1/ns/*, /proc/sysrq-trigger |
| Reverse Shell Spawned | CRITICAL | /dev/tcp/, bash -i, nc -e patterns |
| Training Data Access | NOTICE | Access to /training_data/, /datasets/ dirs |

## Customisation

Add custom rules by creating a `falco_rules.local.yaml` file and mounting it alongside the default rules:

```yaml
- rule: My Custom AI Rule
  desc: Detect custom AI-specific behaviour
  condition: evt.type=execve and proc.name=my_process
  output: "Custom detection (%proc.name %container.id)"
  priority: WARNING
  tags: [aisec, custom]
```

## Integration

Falco findings are automatically mapped to OWASP LLM Top 10, OWASP Agentic Security, and NIST AI RMF frameworks. Five correlation rules combine Falco alerts with static analysis findings for compound risk identification.
