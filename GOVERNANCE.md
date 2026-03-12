# Governance

## Project Role

This repository is the **DIF TAAWG protocol reference implementation** for MCP-I (Model Context Protocol Identity). It provides a TypeScript implementation of the MCP-I specification for adding cryptographic identity, delegation chains, and non-repudiation proofs to AI agent interactions.

## Maintainers

| Name | Email | Role |
|------|-------|------|
| Dylan Hobbs | dylanjhobbs@gmail.com | Initial Maintainer |

## Decision Making

### Non-Breaking Changes

Non-breaking changes follow a **lazy consensus** model:
- Proposed via pull request
- Approved after 72 hours with no objections from maintainers
- Any maintainer may merge after the waiting period

### Breaking Changes

Breaking changes to the specification require **explicit vote**:
- Labeled with `breaking-change`
- Requires approval from majority of active maintainers
- Minimum 7-day discussion period
- Changes affecting SPEC.md are coordinated with DIF TAAWG

## Relationship to DIF TAAWG

This repository implements the MCP-I specification under development in the **Decentralized Identity Foundation (DIF) Trust and Authorization for AI Working Group (TAAWG)**.

- **Spec decisions** are made in the working group
- **Implementation decisions** are made here
- This repo tracks the authoritative spec as it evolves in TAAWG
- Spec divergences should be reported as issues and resolved with the working group

## Becoming a Maintainer

To become a maintainer:

1. **Sustained contributions** — Demonstrate ongoing commitment through quality PRs, issue triage, and community engagement
2. **DCO compliance** — All contributions must be signed off per the Developer Certificate of Origin
3. **Nomination** — Nominated by an existing maintainer
4. **Approval** — Approved by majority vote of existing maintainers

## Relationship to Linux Foundation

This project is **targeting Linux Foundation sandbox donation**.

- All contributions must comply with **DCO (Developer Certificate of Origin)** requirements
- Contributors sign off commits with `git commit -s`
- CLA/DCO requirements apply to all contributions
- Upon acceptance into LF, governance may be updated to align with LF requirements

## Code of Conduct

All participants are expected to follow professional conduct standards. Harassment, discrimination, and disruptive behavior are not tolerated.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
