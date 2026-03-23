# Visual 2: Inspector Consent Flow — Recording Guide

**What:** Screen recording of MCP Inspector showing the consent-basic delegation flow.  
**Who records:** Brian (needs screen capture: Kap, CleanShot, or QuickTime).  
**Time:** ~30 seconds.

---

## Setup

```bash
cd ~/Documents/@kya-os/modelcontextprotocol-identity/mcp-i-core

# Build everything
npm run build

# Start Inspector with stdio (no HTTP needed)
npx @modelcontextprotocol/inspector npx tsx examples/consent-basic/server.ts
```

Inspector opens at `http://localhost:6274`. The server runs via stdio behind the scenes.

## Recording Steps

Start recording, then:

1. **Connect** — Click "Connect" in Inspector. You'll see the server connect.

2. **List tools** — Click the "Tools" tab. You should see:
   - `checkout` (protected — requires delegation)
   - `search` (public)
   - `_mcpi` (protocol tool)

3. **Call `search`** — Enter any query. Response comes back with `_meta.proof` attached.  
   *Pause briefly so viewers can see the proof in the response.*

4. **Call `checkout`** — Enter an item name. Response should include:
   - `needs_authorization: true`
   - A `consent_url`
   - A `resume_token`

5. **Open consent URL** — Click/paste the consent URL in a browser tab. Approve.

6. **Retry `checkout`** — Call checkout again (with same args). This time:
   - Response succeeds
   - `_meta.proof` is attached with full JWS signature

7. **Stop recording.**

## What to Highlight (annotations/callouts)

If your screen recorder supports annotations:
- Circle the `_meta.proof` object in step 3
- Circle `needs_authorization` in step 4
- Circle the successful response + proof in step 6

## Fallback: If Inspector Doesn't Show Proofs

Inspector may not render `_meta` fields in the UI. If so:
- Open browser DevTools → Network tab
- Filter for the websocket/fetch responses
- The raw JSON will show `_meta.proof`

## Output

Save as `rendered/inspector-consent-flow.mp4` (or `.gif` if you convert it).
Recommended: 1280×720 or 1440×900, dark mode if possible.
