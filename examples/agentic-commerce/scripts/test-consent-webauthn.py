#!/usr/bin/env python3
"""Exercise real browser WebAuthn using a Chromium virtual FIDO2 authenticator.

The test starts isolated RP/merchant ports, creates temporary test keys, uses the
existing registration page and actual consent Approve grant button, then checks
MCP allow, software revoke, revoked denial and the witnessed audit bundle.
It never reads or changes the stage's credentials or running servers.
Requires Python playwright and Chromium; CHROMIUM may select an installed Chrome.
"""
import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.request import urlopen
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
from browser_consent import APPROVE, DENY, SCREEN, assert_capability_consent, assert_mobile_consent

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--outdir', default=None)
parser.add_argument('--google-identity', action='store_true', help='Use a fictional signed Google ID-token fixture with real server cryptographic verification, then real browser WebAuthn.')
args = parser.parse_args()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


async def browser_check(merchant, rp, output, state):
    errors = []
    report = {'ok': False, 'authenticator': 'Chromium virtual FIDO2', 'identity': 'Locally signed fictional Google token; Google certificate transport mocked' if args.google_identity else 'Local RP authority; no Google account', 'checks': [], 'browserErrors': errors}
    async with async_playwright() as playwright:
        executable = os.environ.get('CHROMIUM')
        browser = await playwright.chromium.launch(headless=True, **({'executable_path': executable} if executable else {}))
        context = await browser.new_context(viewport={'width': 1440, 'height': 900})
        if args.google_identity:
            # No Google account is used by this test. The official ID-token verifier
            # runs on a locally signed fixture token; real GIS requires a client ID.
            await context.route('https://accounts.google.com/**', lambda route: route.abort())
        page = await context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        cdp = await context.new_cdp_session(page)
        await cdp.send('WebAuthn.enable')
        authenticator = await cdp.send('WebAuthn.addVirtualAuthenticator', {'options': {'protocol': 'ctap2', 'transport': 'internal', 'hasResidentKey': False, 'hasUserVerification': False, 'isUserVerified': False, 'automaticPresenceSimulation': True}})
        if args.google_identity:
            await page.goto(rp + '/setup-key.html', wait_until='networkidle')
            await expect(page.locator('#go')).to_be_disabled()
            await expect(page.locator('#account-name')).to_contain_text('Sign in')
            await page.locator('#sign-in').click()
            await expect(page).to_have_url(rp + '/auth/login')
            signed_in = await page.evaluate('''async () => {
              const options = await (await fetch('/auth/google/options')).json();
              const token = await (await fetch('/test/google-token', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({nonce:options.nonce})})).json();
              const response = await fetch('/auth/google/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(token)});
              return {status:response.status,body:await response.json()};
            }''')
            assert signed_in['status'] == 200, signed_in
            assert signed_in['body']['account']['displayName'] == 'Workshop Test Human'
            await page.goto(rp + signed_in['body']['returnTo'], wait_until='networkidle')
            await expect(page.locator('#account-name')).to_have_text('Workshop Test Human')
            await expect(page.locator('#go')).to_be_enabled()
            await page.screenshot(path=str(output / 'google-account-before-passkey.png'), full_page=True)
            report['checks'].append('Google account session created through real nonce, cookie and signature verification using a fictional local token; no live Google sign-in claimed')
        else:
            await page.goto(merchant + '/setup-key.html', wait_until='networkidle')
        await expect(page.locator('#registered')).to_contain_text('No passkey registered yet')
        await page.locator('#label').fill('Virtual workshop badge')
        await page.get_by_role('button', name='Register this passkey').click()
        await expect(page.locator('#out')).to_contain_text('registered ✓', timeout=15_000)
        report['checks'].append('Existing registration page verified a real browser FIDO2 attestation')
        if args.google_identity:
            authenticators = json.loads((state / 'data/authenticators.json').read_text())
            assert authenticators[-1]['accountId'] == signed_in['body']['account']['accountRef']
            report['checks'].append('Server-bound opaque Google account reference persisted on the verified passkey registration')
            await page.screenshot(path=str(output / 'google-account-passkey-registered.png'), full_page=True)

        async def order():
            response = await context.request.post(merchant + '/api/act/order', data={'product': 'risotto', 'quantity': 2})
            assert response.ok, await response.text()
            result = await response.json()
            return json.loads(result['result']['content'][0]['text'])

        challenge = await order()
        assert challenge['error'] == 'needs_authorization'
        fields = {'tool': 'place_order', 'scopes': json.dumps(challenge['scopes']), 'selected_scopes': json.dumps(challenge['scopes']), 'agent_did': parse_qs(urlparse(challenge['authorizationUrl']).query)['agent_did'][0], 'session_id': challenge['resumeToken']}
        response = await context.request.post(rp + '/consent/approve', data=fields)
        assert response.status == 409, await response.text()
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        report['checks'].append('Registered authenticator flag rejects approval without an assertion')
        await context.request.post(merchant + '/api/act/reset', data={})
        challenge = await order()
        assert challenge['authorizationUrl'].startswith(rp + '/consent?')
        await page.goto(challenge['authorizationUrl'], wait_until='networkidle')
        pending = json.loads((state / 'var/consent/flows.json').read_text())
        bindings = pending['flows'][challenge['resumeToken']]['bindings']
        await assert_capability_consent(page, bindings)
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        report['checks'].append('Actual capability component displays bound GS1 scope, agent, merchant, cap and expiry; deselection disables approval without issuing a VC')
        if args.google_identity:
            await expect(page.locator('#human-account-name')).to_have_text('Workshop Test Human')
        await page.screenshot(path=str(output / 'webauthn-ready.png'), full_page=True)
        if args.google_identity:
            await page.set_viewport_size({'width': 390, 'height': 844})
            await assert_mobile_consent(page)
            await page.screenshot(path=str(output / 'google-consent-ready-mobile.png'), full_page=True)
            await page.set_viewport_size({'width': 1440, 'height': 900})

        # Exercise cancellation of a real pending navigator.credentials.get call.
        # Only the user-presence simulation is paused; no fake assertion is returned.
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId': authenticator['authenticatorId'], 'enabled': False})
        await page.evaluate('''() => {
          const nativeGet = navigator.credentials.get.bind(navigator.credentials);
          navigator.credentials.get = options => {
            navigator.credentials.get = nativeGet;
            window.__cancelConsentPasskey = new AbortController();
            return nativeGet({...options, signal: window.__cancelConsentPasskey.signal});
          };
        }''')
        await page.locator(APPROVE).click()
        await page.wait_for_function('window.__cancelConsentPasskey !== undefined')
        await expect(page.locator(APPROVE)).to_be_disabled()
        await expect(page.locator(DENY)).to_be_disabled()
        await expect(page.locator(SCREEN).get_by_role('checkbox')).to_be_disabled()
        await page.evaluate('window.__cancelConsentPasskey.abort()')
        await expect(page.locator(APPROVE)).to_be_enabled()
        await expect(page.locator(DENY)).to_be_enabled()
        await expect(page.locator('#decision-status')).to_have_text('Passkey confirmation did not complete. No grant was issued. Try again.')
        assert (await context.request.get(rp + '/api/rp/delegation')).status == 404
        pending = json.loads((state / 'var/consent/flows.json').read_text())
        assert pending['flows'][challenge['resumeToken']]['state'] == 'pending'
        report['checks'].append('Canceled real passkey request keeps the grant pending and issues no VC; controls unlock for a retry')
        await cdp.send('WebAuthn.setAutomaticPresenceSimulation', {'authenticatorId': authenticator['authenticatorId'], 'enabled': True})
        lost_response = {'committed': False}
        approval_posts = []
        if args.google_identity:
            page.on('request', lambda request: approval_posts.append(request.url)
                    if request.method == 'POST' and request.url == rp + '/consent/approve' else None)

            async def drop_committed_response(route):
                # Commit through the actual authenticated server and only then
                # simulate a connection failure on its way back to the browser.
                response = await route.fetch()
                assert response.ok, await response.text()
                lost_response['committed'] = True
                await route.abort('failed')

            await page.route(rp + '/consent/approve', drop_committed_response, times=1)
        await page.locator(APPROVE).click()
        expected_decision = 'Grant issued. Workshop Test Human → passkey confirmed → signed grant → Acme Shopping Agent. Retry the same order in Claude.' if args.google_identity else 'Grant issued. Retry the same order in Claude.'
        await expect(page.locator('#decision-status')).to_have_text(expected_decision, timeout=20_000)
        if args.google_identity:
            await expect(page.locator('#consent-ceremony')).to_be_hidden()
            assert lost_response['committed'] and len(approval_posts) == 1, 'Response loss must recover the committed grant without posting another approval'
            report['checks'].append('A deliberately dropped real approval response recovers the committed grant and account from read-only status, without submitting approval again')
        await page.screenshot(path=str(output / 'webauthn-grant-issued.png'), full_page=True)
        pending = json.loads((state / 'var/consent/flows.json').read_text())
        hardware_events = [event for event in pending['events'] if event['type'] == 'consent.approved' and event['payload'].get('authentication', {}).get('method') == 'webauthn']
        assert hardware_events and hardware_events[-1]['payload']['authentication']['credentialId']
        assert hardware_events[-1]['payload']['authentication']['aaguid']
        assert not any(event['type'] == 'credential.verified' for event in pending['events']), 'Passkey proof must not be mislabeled as a credential verification'
        assert hardware_events[-1]['payload']['approvedScopes'] == challenge['scopes']
        if args.google_identity:
            assert hardware_events[-1]['payload']['authentication']['human']['accountRef'] == signed_in['body']['account']['accountRef']
            credentials = list((state / 'var').rglob('delegation-*.json'))
            if not credentials:
                credentials = list((state / 'data').rglob('delegation-*.json'))
            assert credentials, 'Issued VC missing from isolated state'
            vc = json.loads(credentials[-1].read_text())
            linked = vc['credentialSubject']['delegation']['metadata']['demoConsent']
            assert linked['human']['accountRef'] == signed_in['body']['account']['accountRef']
            assert linked['authentication']['method'] == 'webauthn'
            assert linked['consentRef'].startswith('sha256:')
            assert 'fixture-human-not-a-real-google-account' not in json.dumps(vc)
            assert 'fictional-human@example.test' not in json.dumps(vc)
            report['checks'].append('Issued signed VC metadata links the same provider account, verified passkey, consent reference and agent while omitting raw subject and email')
        report['checks'].append('Actual consent button completed navigator.credentials.get, bound assertion verification and VC issuance')
        report['checks'].append('Consent audit event commits authenticator credential ID, AAGUID and issuance-intent hash')
        allowed = await order()
        assert allowed.get('ok') is True, allowed
        report['checks'].append('Same MCP order allowed with the new VC, holder proof and resume token')
        if args.google_identity:
            await page.goto(merchant + '/', wait_until='networkidle')
            await expect(page.locator('#c-human')).to_contain_text('Workshop Test Human')
            await expect(page.locator('#verdict-code')).to_have_text('GRANT ACTIVE · READY TO ORDER')
            await page.keyboard.press('p')
            await page.screenshot(path=str(output / 'google-human-to-agent-projector.png'), full_page=True)
            await page.set_viewport_size({'width': 390, 'height': 844})
            await page.screenshot(path=str(output / 'google-human-to-agent-projector-mobile.png'), full_page=True)
            await page.set_viewport_size({'width': 1440, 'height': 900})
            report['checks'].append('Projector renders the account to passkey to consent to signed agent grant relationship')
        response = await context.request.post(rp + '/api/rp/revoke', data={})
        assert response.ok, await response.text()
        denied = await order()
        assert 'revoked' in json.dumps(denied).lower(), denied
        report['checks'].append('KEY_WEBAUTHN=0 keeps revocation software-only despite the registered issuance key')
        report['checks'].append('Next MCP order denied after the RP status-list bit flipped')
        response = await context.request.post(merchant + '/api/act/export', data={})
        assert response.ok, await response.text()
        for filename, code in [('bundle.json', 0), ('bundle.tampered.json', 1)]:
            result = subprocess.run(['python3', str(ROOT / 'scripts/verify-ledger.py'), str(state / 'var/audit' / filename), '--keys', str(state / 'var/audit/keys.json'), '--quiet'], capture_output=True, text=True)
            assert result.returncode == code, result.stdout + result.stderr
        report['checks'].append('Honest witnessed bundle verified and tampered bundle rejected')
        assert not errors, errors
        report['ok'] = True
        (output / ('google-identity-browser-report.json' if args.google_identity else 'webauthn-browser-report.json')).write_text(json.dumps(report, indent=2))
        print(json.dumps(report, indent=2))
        await browser.close()


def main():
    output = Path(args.outdir or tempfile.mkdtemp(prefix='kya-webauthn-evidence-')).resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='kya-webauthn-state-') as directory:
        state = Path(directory)
        rp_port, merchant_port = free_port(), free_port()
        while merchant_port == rp_port:
            merchant_port = free_port()
        env = {**os.environ, 'DEMO_VAR_DIR': str(state / 'var'), 'DEMO_DATA_DIR': str(state / 'data'), 'RP_PORT': str(rp_port), 'MERCHANT_PORT': str(merchant_port), 'DEMO_GOOGLE_IDENTITY_TEST': '1' if args.google_identity else '0'}
        log = (output / 'fixture.log').open('w')
        process = subprocess.Popen(['node', '--import', 'tsx', 'scripts/consent-browser-fixture.ts'], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        merchant, rp = f'http://localhost:{merchant_port}', f'http://localhost:{rp_port}'
        try:
            deadline = time.monotonic() + 20
            while True:
                try:
                    with urlopen(merchant + '/api/state', timeout=1) as response:
                        assert response.status == 200
                    break
                except Exception:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError((output / 'fixture.log').read_text())
                    time.sleep(.2)
            asyncio.run(browser_check(merchant, rp, output, state))
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()
    print(f'Virtual WebAuthn evidence: {output}')


if __name__ == '__main__':
    main()
