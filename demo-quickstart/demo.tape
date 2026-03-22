Output demo.gif
Set FontSize 14
Set Width 1000
Set Height 580
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Shell "./demo-shell.sh"

Sleep 500ms

# ── Step 1: Install ──────────────────────────────────────
Type "npm install @mcp-i/core"
Enter
Sleep 3s

# ── Step 2: Show the wrapped server ─────────────────────
Type "cat server.ts"
Enter
Sleep 5s

# ── Step 3: Start it ─────────────────────────────────────
Type "npx tsx server.ts"
Enter
Sleep 4s

# ── Step 4: Stop and show proof example ──────────────────
Ctrl+C
Sleep 0.5s
Type "# Every tool response now includes a signed proof:"
Enter
Sleep 1s
Type "cat example-response.json"
Enter
Sleep 5s
