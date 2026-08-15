# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BraZKIL is the reference implementation (Proof of Concept) for a SBSeg 2026 paper (`BraZKIL.tex`). It demonstrates a hybrid age-verification architecture combining SSI (self-sovereign identity), DIDs, SD-JWT Verifiable Credentials and Selective Disclosure, built to comply with Brazil's ECA Digital (age verification) and LGPD (data minimization). The core claim under test: a Verifier should learn `age_over_18: true` and nothing else — no CPF, name, or birthdate — while a Validator still checks those attributes once against an authoritative source (Serpro's Datavalid demo API).

The PoC is a set of 4 local FastAPI microservices plus a Docker-based `walt.id` wallet, wired together to reenact the full issuance → redemption → presentation → verification lifecycle described in the paper. `BraZKIL.tex` §5 defines the exact functional claims (Table 2) and latency benchmarks (Table 3) that `evaluate_brazkil.py` reproduces — when in doubt about *why* a piece of code exists, check what claim/section of the paper it supports.

## Running the stack

```bash
pip install -r requirements.txt
chmod +x start_brazkil.sh   # first time only
./start_brazkil.sh          # starts VDR, Validator, Issuer, Verifier + walt.id wallet (Docker), waits for /health on each
./start_brazkil.sh stop     # kills the 4 uvicorn processes (does not stop Docker)
```

`start_brazkil.sh` also detects the Docker bridge/compose network gateway and exports `ISSUER_BASE_URL` / `VERIFIER_BASE_URL` pointing at it (not `127.0.0.1`), because the walt.id wallet runs in a container and must call back into the host-side Issuer/Verifier. It also opens an iptables rule for ports 8000–8003 on the docker bridge interface. If you run a service manually instead of via the script, remember these env vars matter for OID4VCI/OID4VP callbacks from the wallet.

To run a single service manually (e.g. while iterating):
```bash
python -m uvicorn vdr.main:app --port 8001 --reload
python -m uvicorn validator_datavalid.main:app --port 8000 --reload
python -m uvicorn issuer.main:app --port 8002 --reload
python -m uvicorn verifier.main:app --port 8003 --reload
```
Start the VDR first — Issuer bootstraps its DID and registers it in the VDR on first run (see `issuer/.issuer_identity.json`, created automatically).

Wallet stack (walt.id, vendored under `wallet/waltid-identity/`, own nested git repo — not a submodule):
```bash
cd wallet/waltid-identity/docker-compose && docker compose up -d   # wallet UI at localhost:7101
docker compose down                                                 # to tear down
```

There is no lint/build tooling configured (no pyproject/ruff/pytest) — this is a script-driven functional PoC, not a packaged library.

## Testing / evaluation

There's no pytest suite. Both scripts require the full stack (`./start_brazkil.sh`) to be up and hit it over HTTP on localhost:

```bash
python test_flow.py         # single end-to-end OID4VCI Pre-Authorized Code flow (issue -> token -> credential)
python evaluate_brazkil.py  # reproduces paper Table 2 (functional claims, PASS/FAIL) and Table 3 (latency benchmarks, N=50 for /validate, N=1000 for other ops)
```

`verifier/main.py`'s `POST /verifier/simulate` endpoint is also a full end-to-end driver (holder keygen → issue → token → credential → OID4VP present) usable without a real wallet — useful for exercising the flow interactively via `/docs` while debugging.

## Architecture

Five independent processes, no shared runtime state — everything is coordinated over HTTP on localhost, each service in its own top-level package:

- **`vdr/`** (port 8001) — Verifiable Data Registry / Trust Registry. The only service with real persistence: SQLite (`trust_registry.db`) via SQLAlchemy (`vdr/models.py`), three tables — `authorized_issuers` (DID Documents), `credential_status` (ACTIVE/SUSPENDED/REVOKED per credential_id), `validation_audits` (ephemeral pass/fail audit trail, deliberately **no PII**). Also acts as the W3C DID Resolver every other service calls to fetch public keys.
- **`validator_datavalid/`** (port 8000) — wraps the Serpro Datavalid demo API (`validator_datavalid/client.py`). On network failure or non-200/quota-exceeded responses it transparently falls back to a deterministic local mock (`_get_mock_response`, keyed off the fixed test CPF `25774435016` / "Manuela Elisa da Mota" / `1975-06-04`) so the PoC still runs offline — don't be surprised by `[DATAVALID MOCK]` log lines, that's expected behavior, not a bug. After validating, it POSTs only `{validation_id, is_valid, created_at}` to the VDR (`validator_datavalid/service.py::notify_vdr_audit`) — never the CPF/name/birthdate.
- **`issuer/`** (port 8002) — the OID4VCI middleware and the only stateful (in-memory dict) service besides its identity file. `issuer/policy.py::evaluate_issuance_policy` is the single gate deciding whether a validated citizen gets `age_over_18=True`; `issuer/sd_jwt.py::generate_sd_jwt_vc` builds the SD-JWT VC per IETF SD-JWT VC draft (hashes in `_sd`, two disclosures: `age_over_18` and `birthdate`, `cnf.jwk` binds the credential to the holder's key). Implements the Pre-Authorized Code flow (`/issuer/issue` → `/issuer/token` → `/issuer/credential`) plus OID4VCI/OAuth discovery endpoints the walt.id wallet needs (`/.well-known/openid-credential-issuer`, `/.well-known/openid-configuration`). Also serves the citizen-facing form at `/portal` (`issuer/portal.html`).
- **`verifier/`** (port 8003) — the OID4VP relying party, demoed as a wine shop (`verifier/wine_shop.html`, age-gated purchase). `verifier/verify.py::verify_presentation` is the core 4-step pipeline (issuer signature via VDR → revocation status via VDR → disclosure hash integrity → Key Binding JWT proof-of-possession, nonce+aud+sd_hash) and is written to always return every step's pass/fail — read it when debugging *why* a presentation was denied, the `steps` list is the source of truth, not just the final `approved` bool.
- **`wallet/waltid-identity/`** — vendored open-source walt.id wallet (its own git history, treat as a mostly-read-only dependency; don't try to `cd` into it and modify it casually — check `wallet/waltid-identity/README.md`/`README-old.md` if you need to touch it).
- **`shared/did.py`** — the only code imported by all four Python services. Defines the `did:brazkil:<uuid>` method: EC P-256 keygen, JWK/DID Document construction, and `resolve_public_key_from_did_document`/`verify_signature` used everywhere a service needs to check another service's/holder's signature. Every service does `sys.path.insert(0, "..")` at import time specifically to reach this module — keep that pattern if you add new service entry points.

**Credential shape**: `<SD-JWT header.payload.signature>~<disclosure_age_over_18>~<disclosure_birthdate>`, and once presented with holder binding: `...~<Key Binding JWT>`. The Issuer always embeds *both* disclosures at issuance time; the wallet/holder chooses which to reveal at presentation time (the `/verifier/simulate` demo only ever reveals `age_over_18`, leaving `birthdate` selectively withheld — this asymmetry is the whole point of the architecture, not an oversight).

**Trust flow for a presentation**: Verifier never talks to the Issuer directly. It resolves the Issuer's DID Document from the VDR to check the SD-JWT signature, and separately queries the VDR's status-list endpoint for revocation — the VDR is the sole trust anchor both services rely on.

## Working in this repo

- All PII-adjacent code paths (Validator → VDR, Issuer → VDR) are intentionally minimal in what they persist/transmit. If you touch `notify_vdr_audit`, `_register_credential_status`, or the VDR schemas, preserve the "no CPF/name/birthdate leaves the Validator/Issuer" invariant — it's a functional claim the paper and `evaluate_brazkil.py` assert on.
- `format: "dc+sd-jwt"` (not `"vc+sd-jwt"`) is required in Issuer metadata for walt.id v0.23+ compatibility; the credential's own `typ` header still says `vc+sd-jwt`. See the comments in `issuer/main.py::issuer_metadata` before changing either.
- `issuer/main.py` has a `DEBUG_LOG_REQUESTS` raw request/response logging middleware, on by default (env `DEBUG_LOG_REQUESTS=false` to disable) — it was added specifically to debug walt.id OID4VCI interop and is noisy in logs by design.
- Ports are fixed and hardcoded in several places (8000/8001/8002/8003, wallet 7101); if you change one, grep across all five service dirs plus `start_brazkil.sh` and `evaluate_brazkil.py`.
