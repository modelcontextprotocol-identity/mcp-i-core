#!/usr/bin/env python3
"""Drive the console through every beat with a headless browser and save
screenshots — a smoke test for the UI wiring (SSE, rendering, keys) and the
frames for the README. Requires `pip install playwright` + a Chromium.

    python3 scripts/screenshot-run.py [outdir] [--presenter]
"""
import asyncio, sys, os, json
from playwright.async_api import async_playwright

OUT = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith('--') else '/tmp/console-shots'
PRESENTER = '--presenter' in sys.argv
os.makedirs(OUT, exist_ok=True)

async def shot(page, name):
    await page.wait_for_timeout(700)
    await page.screenshot(path=f'{OUT}/{name}.png', full_page=True)
    print('saved', name)

async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(executable_path=os.environ.get('CHROMIUM', '/opt/pw-browsers/chromium'))
        page = await b.new_page(viewport={'width': 1440, 'height': 900})
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.on('console', lambda m: errors.append(m.text) if m.type == 'error' else None)
        await page.goto('http://localhost:4949/')
        await page.wait_for_timeout(1500)
        if PRESENTER:
            await page.keyboard.press('p')
        await shot(page, '00-ready')
        for key, name, wait in [('0', '01-discover', 800), ('1', '02-order', 1500), ('2', '03-wrong-product', 1200), ('3', '04-over-cap', 1200), ('5', '05-stolen', 1200)]:
            await page.keyboard.press(key)
            await page.wait_for_timeout(wait)
            await shot(page, name)
        await page.keyboard.press('v'); await page.wait_for_timeout(2500); await shot(page, '06-python')
        await page.keyboard.press('k'); await page.wait_for_timeout(1500); await shot(page, '07-revoked')
        await page.keyboard.press('4'); await page.wait_for_timeout(1500); await shot(page, '08-retry-denied')
        await page.keyboard.press('r'); await page.wait_for_timeout(1500); await shot(page, '09-reset')
        seal = await page.inner_text('#seal')
        code = await page.inner_text('#verdict-code')
        print(json.dumps({'seal': seal, 'code': code, 'errors': errors}, indent=1))
        await b.close()

asyncio.run(main())
