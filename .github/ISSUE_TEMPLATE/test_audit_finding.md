---
name: Test Audit Finding
about: A bug or logic gap discovered during Phase 1 test quality audit
labels: bug, test-audit
---

**Module**: <!-- e.g., delegation/vc-verifier.ts -->

**Audit Test**: <!-- e.g., src/__tests__/audit/vc-roundtrip.test.ts -->

**Test Name**: <!-- e.g., "reject VC with tampered credentialSubject" -->

**Describe the finding**
<!-- What does the test expect vs. what actually happens? -->

**Severity**: <!-- Critical / High / Medium / Low -->
<!-- Critical = security bypass; High = incorrect behavior in security path; Medium = logic gap; Low = cosmetic/spec compliance -->

**Root Cause Analysis**
<!-- Where in the source code is the bug? Include file + line number if possible. -->

**Reproduction**
```typescript
// Minimal test code that demonstrates the issue
```

**Expected behavior**
<!-- What should happen per the spec/design? -->

**Actual behavior**
<!-- What happens currently? -->

**Spec Reference**
<!-- Which section of SPEC.md or W3C spec is violated? -->
