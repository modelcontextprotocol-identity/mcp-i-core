# Quickstart Demo (VHS)

Terminal GIF for the docs quickstart page showing zero-to-MCP-I in ~20 seconds.

## How it works

VHS runs real commands in a real shell, so everything here needs to actually work.
The tape runs from this directory with mock scripts for `npm install` and server startup.

## Setup

```bash
brew install charmbracelet/tap/vhs  # if not installed
cd demo-quickstart
chmod +x mock-install.sh mock-run.sh
```

## Record

```bash
vhs demo.tape
```

This produces `demo.gif` in the current directory.

## What the demo shows

1. `npm install @mcp-i/core` → (mocked fast install output)
2. `cat server.ts` → shows the complete wrapped server (real file)
3. `npx tsx server.ts` → (mocked server startup with DID + proof confirmation)
4. `cat example-response.json` → shows a tool response with signed proof

## Customizing

- Edit `server.ts` to change the example code shown
- Edit `mock-run.sh` to change server startup output
- Edit `example-response.json` to change the proof example
- Edit `demo.tape` to adjust timing, theme, or font size

## Notes

- The `npm install` and `npx tsx` commands are aliased to mock scripts via the tape's
  shell setup. This avoids real package installation and server startup during recording.
- The `server.ts` file matches the actual `@mcp-i/core` API (`withMCPI` + `NodeCryptoProvider`).
- Transport shown is `stdio` (not SSE) since that's what `withMCPI` wraps out of the box.
