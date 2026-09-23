"""Skill Doctor Lite — rule catalog.

Data-driven, versioned, auditable signature rules. Published rules can be
studied by attackers; that is the honest signature-game tradeoff (see
PRODUCT.md). The design answer: rules are pinned per release and every report
carries rules_version, so a "clean" verdict is auditable — never a trust
certificate.

Each rule is a dict:
    id          unique rule identifier
    category    prompt-injection | exfiltration | approval-disabling | embedded-secret
    pattern     regex string (compiled with re.IGNORECASE)
    severity    critical | high | medium | low
    title       short human title
    guidance    what the operator should do about a hit
"""

RULES_VERSION = "1.0.0"

CATEGORIES = (
    "prompt-injection",
    "exfiltration",
    "approval-disabling",
    "embedded-secret",
)

SEVERITIES = ("critical", "high", "medium", "low")

RULES = [
    # ------------------------------------------------------------------
    # prompt-injection: instruction text that tries to steer the agent
    # ------------------------------------------------------------------
    {
        "id": "PI-001",
        "category": "prompt-injection",
        "pattern": r"ignore\s+(all\s+)?(previous|prior|earlier)\s+instructions",
        "severity": "critical",
        "title": "Instruction-override: 'ignore previous instructions'",
        "guidance": ("Classic prompt-injection opener. Do not install until the "
                     "line is removed and the skill's provenance is verified."),
    },
    {
        "id": "PI-002",
        "category": "prompt-injection",
        "pattern": r"disregard\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules)",
        "severity": "critical",
        "title": "Instruction-override: 'disregard prior instructions'",
        "guidance": ("Instruction-override directive aimed at the host agent. "
                     "Remove before installing."),
    },
    {
        "id": "PI-003",
        "category": "prompt-injection",
        "pattern": r"(from\s+now\s+on,?\s+)?you\s+are\s+now\b",
        "severity": "high",
        "title": "Identity override: 'you are now'",
        "guidance": ("Attempts to replace the agent's identity/role. Treat as "
                     "an injection attempt unless you wrote this line yourself."),
    },
    {
        "id": "PI-004",
        "category": "prompt-injection",
        "pattern": r"forget\s+(everything|all)\s+you\s+(were|have\s+been)\s+(told|given|taught)",
        "severity": "critical",
        "title": "Memory wipe: 'forget everything you were told'",
        "guidance": ("Attempts to erase the agent's standing instructions. "
                     "Remove before installing."),
    },
    {
        "id": "PI-005",
        "category": "prompt-injection",
        "pattern": r"(reveal|print|show|output|display)\s+(me\s+)?(your|the)\s+(system\s+prompt|system\s+instructions|hidden\s+instructions)",
        "severity": "high",
        "title": "Prompt-extraction: requests the system prompt",
        "guidance": ("Asks the agent to leak its own system instructions. "
                     "Legitimate debugging tools document this explicitly; "
                     "otherwise remove."),
    },
    {
        "id": "PI-006",
        "category": "prompt-injection",
        "pattern": r"act\s+as\s+if\b",
        "severity": "medium",
        "title": "Role-play hook: 'act as if'",
        "guidance": ("Commonly benign in creative writing, but it is also a "
                     "standard injection framing. Review the surrounding "
                     "lines before installing."),
    },
    {
        "id": "PI-007",
        "category": "prompt-injection",
        "pattern": r"(white\s*-?on\s*-?white|font\s*-?size\s*:\s*0|opacity\s*:\s*0|display\s*:\s*none|hidden\s+instruction|invisible\s+instruction)",
        "severity": "high",
        "title": "Hidden-instruction trick (invisible text / styling)",
        "guidance": ("Concealed text is a delivery mechanism for instructions "
                     "the reader never sees. Remove it."),
    },
    {
        "id": "PI-008",
        "category": "prompt-injection",
        "pattern": r"(override|overrule|supersede)\s+(your|the|all)\s+(safety|guardrail|instruction)",
        "severity": "critical",
        "title": "Override directive against safety/instructions",
        "guidance": ("Explicitly tells the agent to override its own safety "
                     "or standing instructions. Do not install."),
    },
    # ------------------------------------------------------------------
    # exfiltration: lines that move secrets or data out to strangers
    # ------------------------------------------------------------------
    {
        "id": "EX-001",
        "category": "exfiltration",
        "pattern": r"\bcurl\b[^|\n]*\|\s*(sh|bash|zsh)\b",
        "severity": "critical",
        "title": "Pipe-to-shell: curl fetched code executed directly",
        "guidance": ("Downloads remote code and runs it without review. "
                     "Fetch and inspect the script first, or do not install."),
    },
    {
        "id": "EX-002",
        "category": "exfiltration",
        "pattern": r"\bwget\b[^|\n]*\|\s*(sh|bash|zsh)\b",
        "severity": "critical",
        "title": "Pipe-to-shell: wget fetched code executed directly",
        "guidance": ("Downloads remote code and runs it without review. "
                     "Fetch and inspect the script first, or do not install."),
    },
    {
        "id": "EX-003",
        "category": "exfiltration",
        "pattern": r"\brequests\.(post|put)\s*\([^)]*\bos\.environ\b",
        "severity": "critical",
        "title": "Environment exfiltration: posts os.environ to a URL",
        "guidance": ("Sends the full process environment (often including "
                     "secrets) to a remote endpoint. Remove or prove the "
                     "destination is yours."),
    },
    {
        "id": "EX-004",
        "category": "exfiltration",
        "pattern": r"\.ssh/(id_rsa|id_ed25519|id_dsa|id_ecdsa)\b",
        "severity": "critical",
        "title": "Private SSH key read",
        "guidance": ("Reads an SSH private key. A skill has no legitimate "
                     "reason to touch private keys. Do not install."),
    },
    {
        "id": "EX-005",
        "category": "exfiltration",
        "pattern": r"\bwebhook\b.{0,80}(api[_-]?key|secret|token|password)",
        "severity": "high",
        "title": "Credential material sent to a webhook",
        "guidance": ("Posts keys, tokens, or passwords to a webhook URL. "
                     "Verify the endpoint is under your control before "
                     "installing."),
    },
    {
        "id": "EX-006",
        "category": "exfiltration",
        "pattern": r"\bopen\s*\([^)]*(\.secret|_secret|credentials?|passwd|shadow)(?![a-zA-Z0-9])",
        "severity": "high",
        "title": "Credential-file read",
        "guidance": ("Opens a file that typically holds secrets or account "
                     "data. Confirm it is read-only local use before "
                     "installing."),
    },
    {
        "id": "EX-007",
        "category": "exfiltration",
        "pattern": r"\bcurl\b[^|\n]*(-d|--data)\b[^|\n]*(password|passwd|secret|api[_-]?key|token)",
        "severity": "high",
        "title": "curl posts credential material to a URL",
        "guidance": ("Sends passwords, secrets, or keys out via curl. "
                     "Verify the destination before installing."),
    },
    # ------------------------------------------------------------------
    # approval-disabling: instructions that neuter the operator's gates
    # ------------------------------------------------------------------
    {
        "id": "AD-001",
        "category": "approval-disabling",
        "pattern": r"never\s+ask\s+for\s+confirmation",
        "severity": "high",
        "title": "Approval bypass: 'never ask for confirmation'",
        "guidance": ("Instructs the agent to skip the human confirmation "
                     "gate. Remove before installing."),
    },
    {
        "id": "AD-002",
        "category": "approval-disabling",
        "pattern": r"(bypass|skip)\s+(the\s+)?approval",
        "severity": "high",
        "title": "Approval bypass: 'bypass/skip approval'",
        "guidance": ("Instructs the agent to skip the approval gate. "
                     "Remove before installing."),
    },
    {
        "id": "AD-003",
        "category": "approval-disabling",
        "pattern": r"disable\s+(the\s+)?(guardrails?|safety|safeguards?)",
        "severity": "high",
        "title": "Safety disable: 'disable guardrails'",
        "guidance": ("Instructs the agent to turn off its own guardrails. "
                     "Do not install."),
    },
    {
        "id": "AD-004",
        "category": "approval-disabling",
        "pattern": r"auto[\s_-]?approve",
        "severity": "high",
        "title": "Auto-approval directive",
        "guidance": ("Instructs the agent to approve its own actions. "
                     "Remove before installing."),
    },
    {
        "id": "AD-005",
        "category": "approval-disabling",
        "pattern": r"(bypass|skip)\s+(human\s+)?review",
        "severity": "medium",
        "title": "Review bypass: 'bypass/skip review'",
        "guidance": ("Asks the agent to skip human review of its work. "
                     "Review the context before installing."),
    },
    {
        "id": "AD-006",
        "category": "approval-disabling",
        "pattern": r"(do\s+not|don't)\s+ask\s+for\s+permission",
        "severity": "medium",
        "title": "Permission gate removal: 'don't ask for permission'",
        "guidance": ("Instructs the agent not to seek permission. Review "
                     "the context before installing."),
    },
    # ------------------------------------------------------------------
    # embedded-secret: literal credential material in the skill text
    # (worded as "possible" — these are heuristics, not proof)
    # ------------------------------------------------------------------
    {
        "id": "SE-001",
        "category": "embedded-secret",
        "pattern": r"\bAKIA[0-9A-Z]{16}\b",
        "severity": "high",
        "title": "Possible embedded secret: AWS access-key pattern",
        "guidance": ("Looks like an AWS access key ID baked into the skill. "
                     "Rotate the key, remove the literal, use a vault. "
                     "This is a pattern match, not proof — verify."),
    },
    {
        "id": "SE-002",
        "category": "embedded-secret",
        "pattern": r"\bsk-(proj-)?[A-Za-z0-9]{20,}\b",
        "severity": "high",
        "title": "Possible embedded secret: sk- API key pattern",
        "guidance": ("Looks like a provider API key baked into the skill. "
                     "Rotate the key, remove the literal, use a vault. "
                     "This is a pattern match, not proof — verify."),
    },
    {
        "id": "SE-003",
        "category": "embedded-secret",
        "pattern": r"(password|passwd|pwd)\s*=\s*[\"'][^\"']{8,}[\"']",
        "severity": "medium",
        "title": "Possible embedded secret: password assigned as a literal",
        "guidance": ("A password-looking literal is assigned in the file. "
                     "Move it to a vault or environment variable. "
                     "This is a pattern match, not proof — verify."),
    },
    {
        "id": "SE-004",
        "category": "embedded-secret",
        "pattern": r"Authorization['\"]?\s*:\s*['\"]?Bearer\s+[A-Za-z0-9_\-]{20,}",
        "severity": "medium",
        "title": "Possible embedded secret: bearer token literal",
        "guidance": ("A bearer token literal appears in the file. Rotate it, "
                     "remove the literal, use a vault. This is a pattern "
                     "match, not proof — verify."),
    },
]


def validate():
    """Raise on any catalog problem: duplicate ids, bad categories,
    bad severities, or a regex that does not compile."""
    import re
    seen = set()
    for rule in RULES:
        rid = rule["id"]
        if rid in seen:
            raise ValueError("duplicate rule id: %s" % rid)
        seen.add(rid)
        if rule["category"] not in CATEGORIES:
            raise ValueError("bad category on %s: %r" % (rid, rule["category"]))
        if rule["severity"] not in SEVERITIES:
            raise ValueError("bad severity on %s: %r" % (rid, rule["severity"]))
        for key in ("pattern", "title", "guidance"):
            if not rule.get(key):
                raise ValueError("missing %s on %s" % (key, rid))
        re.compile(rule["pattern"], re.IGNORECASE)
    return len(RULES)


validate()
