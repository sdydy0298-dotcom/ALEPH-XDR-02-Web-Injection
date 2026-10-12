# XDR-02 implementation guide
- Read original ChoiTimo/aleph-defense-starter/xdr/README.md and preserve the official `aleph.xdr.fixture.v1` fixture / `aleph.xdr.result.v1` runner contract.
- Only `xdr/web-injection/decide.mjs` implements the scoring function, with no imports, filesystem, network, external dependencies, or time-dependent behavior.
- `confidence >= 0.85` = block, `confidence >= 0.50` = alert, otherwise record.
- Repeated, clear web injection signals with source evidence may cause a temporary deny rule; ambiguous and benign events must not.
- Never copy actual keys, passwords, cookies, raw request bodies or tokens into logs, build output or source. Use only the upstream synthetic training fixture.
- Existing policies in `ztna/rules.json` are read only; dynamic rules live in `xdr/temporary-deny.json` and expire after 15 minutes.
- Offline `npm run xdr:run -- web-injection` deterministically regenerates result, notifications and temporary denies. `npm test` validates 26 original alerts and behavioral edge cases.
- No actual Wazuh installation or operational ZTNA is attached; Vercel hosts an explanatory static simulation.
