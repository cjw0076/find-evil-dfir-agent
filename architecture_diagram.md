# Architecture Diagram

This project uses a read-only evidence pipeline with architectural guardrails,
not just prompt instructions. The default build runs offline on synthetic
evidence. The live path can point at SIFT/KAPE/Velociraptor-style exports
without changing the agent, detectors, ledger, or eval harness.

```mermaid
flowchart LR
    subgraph Evidence["Evidence sources"]
        S1["Synthetic case library\nmanifest + ground truth"]
        S2["SIFT/KAPE/Velociraptor exports\noptional live triage dir"]
    end

    subgraph Boundary["Read-only boundary"]
        B1["EvidenceSource adapter\nSyntheticSource | LiveTriageSource"]
        B2["EvidenceStore\nstable refs: file:row"]
    end

    subgraph Agent["DFIR triage agent"]
        A1["Ingest artifacts"]
        A2["Initial hypothesis"]
        A3["Refutation checks"]
        A4["Self-correction"]
        A5["Detectors + analyzers"]
    end

    subgraph Tools["Forensic analyzers"]
        T1["Timeline fusion"]
        T2["Process tree"]
        T3["Persistence sweep"]
        T4["LOLBin + PowerShell decode"]
        T5["IOC/TI correlation"]
        T6["Lateral movement graph"]
    end

    subgraph Outputs["Output pipeline"]
        O1["Evidence-linked findings"]
        O2["MITRE ATT&CK mapping"]
        O3["Containment recommendations"]
        O4["Append-only ledger"]
        O5["Replayable trace"]
        O6["Eval report"]
        O7["Web console"]
    end

    S1 --> B1
    S2 --> B1
    B1 --> B2
    B2 --> A1 --> A2 --> A3 --> A4 --> A5
    A5 --> T1
    A5 --> T2
    A5 --> T3
    A5 --> T4
    A5 --> T5
    A5 --> T6
    T1 --> O1
    T2 --> O1
    T3 --> O1
    T4 --> O1
    T5 --> O1
    T6 --> O1
    O1 --> O2 --> O3 --> O4 --> O5 --> O6
    O1 --> O7
```

## Security Boundaries

- Original evidence is opened through read-only adapters. The agent never writes
  back into evidence directories.
- Every conclusion must carry one or more `evidence_refs`, such as
  `sysmon.evtx.jsonl:9`, so a reviewer can trace claims to raw rows.
- The default project does not require an MCP server. If an MCP or live forensic
  tool is added later, it should sit outside the read-only boundary and return
  copied/exported evidence rows, not mutable host access.
- Prompt guardrails are not relied on for evidence integrity. The architectural
  guardrail is the adapter/store split plus append-only outputs.

## Pattern

Autonomous single-agent investigation loop:

`ingest -> hypothesis -> refute -> self-correct -> analyze -> cite evidence -> score`

The loop is visible in `out/trace.json`; the final findings are in
`out/ledger.json`; aggregate accuracy is in `eval/report.json`.
