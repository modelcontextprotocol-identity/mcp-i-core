# Quickstart Visuals

Ready-to-embed assets for the MCP-I quickstart docs page.

| # | Visual | File | Section |
|---|--------|------|---------|
| 3 | Sequence diagram | `sequence-diagram.md` | What's Happening Under the Hood |
| 4 | Annotated proof | `proof-annotated.svg` | What the proof actually looks like |
| 5 | Before/after comparison | `before-after.html` | The Enterprise Scenario |
| 6 | Tool protection flow | `tool-protection.md` | Protect Specific Tools |

## Usage

**Mermaid diagrams** (3 & 6): Copy the fenced code block into your docs. Most frameworks
(Docusaurus, Nextra, Mintlify, Starlight, GitHub) render `mermaid` blocks natively.

**Annotated proof SVG** (4): Embed as `<img src="proof-annotated.svg">` or use your
framework's image component. Renders at any size, retina-ready.

**Before/after HTML** (5): Embed as an iframe or extract the inner markup into a
React/MDX component. Self-contained, no dependencies.
