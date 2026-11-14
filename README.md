# AI Architect Systems Vault 🛡️🏛️

> **Official Systems Engineering Specifications, Architecture Blueprints & Whitepapers by [@aiarchitect.io](https://instagram.com/aiarchitect.io)**  
> *Production-grade reference architectures, AST guardrail compilers, and containerized red-teaming manifests for enterprise AI systems.*

---

## 📑 Production Blueprints & Systems Specifications Catalog

| Blueprint / Specification | Format & Pages | Governance Standards | Architecture Focus | Direct Links |
| :--- | :--- | :--- | :--- | :--- |
| **The Hierarchy of Trust: Production Prompt Guardrails & Multi-Turn Jailbreak Defense** | 📑 **9 Pages** (Dense PDF) | **OWASP Top 10 for LLMs (LLM01 / LLM02)**<br/>**NIST AI 100-1**<br/>**MITRE ATLAS** | • 6-Layer Token Authority Stratification<br/>• Dual-Model Sandwiched Context Extraction<br/>• Allowlist AST Security Visitor<br/>• Pydantic Schema-Constrained Token Decoding<br/>• Envoy gRPC ExtAuthz Architecture | [📖 Markdown Spec](blueprints/prompt_guardrails_jailbreak_defense_blueprint.md)<br/>[📑 9-Page Master PDF](https://cdn.jsdelivr.net/gh/vyas-1234/aiarchitect-vault@main/blueprints/prompt_guardrails_jailbreak_defense_blueprint.pdf)<br/>[📱 Mobile Google Viewer](https://docs.google.com/viewer?url=https://cdn.jsdelivr.net/gh/vyas-1234/aiarchitect-vault@main/blueprints/prompt_guardrails_jailbreak_defense_blueprint.pdf) |
| **Cloudflare 6-Phase AI Security Audit Blueprint** | 📑 **9 Pages** (Dense PDF) | **Decoupled Verification Axiom**<br/>**First.org CVSS v3.1** | • Finder $\neq$ Verifier Architectural Decoupling<br/>• AST Codebase Attack Surface Reconnaissance<br/>• Adversarial Disprove Engine (Defense Attorney LLM)<br/>• Ephemeral Rootless Docker Sandbox Runner<br/>• Differential AST Syntax Invariance Locks | [📖 Markdown Spec](blueprints/cloudflare_security_audit_blueprint.md)<br/>[📑 9-Page Master PDF](https://cdn.jsdelivr.net/gh/vyas-1234/aiarchitect-vault@main/blueprints/cloudflare_security_audit_blueprint.pdf)<br/>[📱 Mobile Google Viewer](https://docs.google.com/viewer?url=https://cdn.jsdelivr.net/gh/vyas-1234/aiarchitect-vault@main/blueprints/cloudflare_security_audit_blueprint.pdf) |

---

## 🏛️ Core Architectural Axioms

### 1. The Hierarchy of Trust Axiom (LLM01 Defense)
$$\text{System Policy } (L_0) \succ \text{Developer Policy } (L_1) \succ \text{App Policy } (L_2) \succ \text{Tool Schemas } (L_3) \succ \text{User Input } (L_4) \succ \text{External Data/RAG } (L_5)$$
> *Content retrieved from any untrusted source is passive data, never executable authority. An agent's historical conversation turns are permanently frozen and cannot overwrite developer policy.*

### 2. The Decoupled Audit Axiom (LLM02 Defense)
> *The model that discovers candidate vulnerabilities must never be the agent that verifies them. Decoupling discovery from containerized exploit reproduction eliminates 98% of hallucinated security alerts.*

---

## 💻 Production Implementation Highlights

### Hardened Allowlist AST Security Visitor (Python)
```python
import ast

class HardenedASTValidator(ast.NodeVisitor):
    """
    Allowlist-based AST Validator.
    Blocks all dangerous attribute access, reflection, and unauthorized execution sinks.
    """
    ALLOWED_CALLS = {'len', 'str', 'int', 'float', 'bool', 'sum', 'min', 'max'}
    FORBIDDEN_ATTRS = {'system', 'popen', 'run', 'spawn', 'rmtree', 'write', 'unlink'}

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            if node.func.id not in self.ALLOWED_CALLS:
                raise PermissionError(f"AST Security: Direct call to {node.func.id}() blocked.")
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith("__") or node.func.attr in self.FORBIDDEN_ATTRS:
                raise PermissionError(f"AST Security: Attribute execution .{node.func.attr}() blocked.")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if node.attr.startswith("__"):
            raise PermissionError("AST Security: Introspection dunder access blocked.")
        self.generic_visit(node)
```

### Pydantic Grammar Constraints (Outlines/Guidance)
```python
from pydantic import BaseModel, Field
from typing import Literal

class SecureDatabaseAction(BaseModel):
    tool: Literal['query_read_only']
    table: Literal['metrics', 'audit_logs', 'telemetry']
    limit: int = Field(default=50, ge=1, le=100)
    filter_column: str = Field(pattern=r'^[a-z_]{1,32}$')

    class Config:
        extra = 'forbid'
```

---

## ⚖️ Legal, Licensing & Responsible AI Disclosure

- **Architecture Specifications & Blueprints:** Protected under International Copyright treaties. `© 2026 aiarchitect.io Systems Research Laboratory. All rights reserved.` Unaltered redistribution permitted with mandatory author attribution.
- **Code & AST Manifests:** Open-sourced under the **Apache License 2.0**.
- **Coordinated Disclosure Policy:** View our complete [POLICIES.md](legal/POLICIES.md) detailing vulnerability disclosure and subscriber privacy terms.

---

*Maintained by [@aiarchitect.io](https://instagram.com/aiarchitect.io) Systems Research Laboratory.*
