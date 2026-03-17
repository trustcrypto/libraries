# NemoClaw / OpenShell integration

This repo now includes a lightweight approval bridge and a central policy /
audit layer that can be used from OpenClaw or NemoClaw.

## Run the bridge on the host

```bash
python -m onlykey_agent_skills.approval_bridge
```

## Environment for MCP server

```bash
export ONLYKEY_APPROVAL_URL=http://127.0.0.1:8765/approve
export ONLYKEY_REQUIRE_ATTESTATION=0
export ONLYKEY_AUDIT_LOG=$HOME/.local/state/onlykey-agent-skills/audit.jsonl
```

## Suggested `openclaw nemoclaw` launch env

```bash
openclaw nemoclaw launch \
  --env ONLYKEY_APPROVAL_URL=http://host.docker.internal:8765/approve \
  --env ONLYKEY_AUDIT_LOG=/tmp/onlykey-audit.jsonl \
  --env ONLYKEY_REQUIRE_ATTESTATION=0
```

## Suggested OpenShell policy fragment

Allow only the bridge endpoint and approved wrapper binaries when you add
wrapper scripts later:

```yaml
network_policies:
  onlykey_bridge:
    name: onlykey-bridge
    endpoints:
      - host: host.docker.internal
        port: 8765
        protocol: rest
        tls: none
        enforcement: enforce
        access: read-write
        binaries:
          - { path: /usr/bin/python3 }
```

## What gets logged

Each protected ssh / git / remote signing action writes JSON lines containing:

- timestamp
- tool
- target
- provider (`openclaw` or `nemoclaw`)
- decision reason
- best-effort hardware attestation metadata
