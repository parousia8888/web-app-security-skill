# JavaScript and TypeScript built-in rule decisions

Status: v0.5.0 M3 implementation record with v0.5.4 additions

This record separates stable detectors from candidates that the bounded, zero-dependency lexical
engine cannot support precisely. A deferred candidate is not executable and is not included in
public rule counts.

## Stable in v0.5.0

| Rule | Promoted signal | Evidence limit |
|---|---|---|
| `js-dynamic-code-execution` | Direct `eval` and `new Function` | No input-flow or reachability proof. |
| `node-child-process-shell-execution` | Resolved `child_process` shell APIs and explicit `shell: true` | No argument-flow proof. |
| `react-dangerous-html-sink` | `dangerouslySetInnerHTML` with `__html` | No value-flow or sanitizer proof. |
| `browser-html-injection-sink` | Direct browser HTML assignments/calls | No value-flow or sanitizer proof. |
| `cors-wildcard-with-credentials` | One object with `origin: "*"` and `credentials: true` | No middleware reachability proof. |
| `node-tls-verification-disabled` | Explicit Node TLS verification-disable literals | No deployment-use proof. |
| `jwt-unsafe-verification-options` | Resolved `jsonwebtoken.verify` with `none` or ignored expiry | No route-use proof. |
| `hardcoded-auth-secret` | Narrow authentication-secret name plus non-placeholder literal | The value is never persisted; validity and deployment use are unknown. |

All eight rules report `suspected`. Each has one vulnerable fixture, one safe near-neighbour,
sanitized structural evidence, a professional and plain-language explanation, security and
functional retests, side effects, rollback conditions and user decisions.

## Added in v0.5.4

| Rule | Promoted signal | Evidence limit |
|---|---|---|
| `js-inline-session-secret` | A non-placeholder literal assigned to a recognized Express session/cookie-session secret option | No proof of production selection, credential validity or external exposure; literal value is never persisted. |
| `js-insecure-cookie-options` | Recognized session/cookie API options explicitly set `secure: false`, `httpOnly: false` or an unsafe `sameSite` value | No proof of HTTPS termination, cookie purpose, middleware reachability or resolved environment override. |

Both rules remain `suspected` and use resolved imports or recognized framework calls rather than
generic property-name matching. Their findings include the same explanation, decision, dual-retest
and rollback contract as the v0.5.0 rules.

## Deferred from the built-in engine

| Candidate | Reason |
|---|---|
| Generic SQL string construction | A useful conclusion needs source-to-query data flow and query-builder/framework semantics. |
| Generic path construction and file access | `join`, `resolve`, and file reads are overwhelmingly legitimate without trust-boundary data flow. |
| Logging password/token/cookie-named variables | Variable names alone do not establish sensitive contents, production logging or redaction behavior. |
| MD5, SHA-1 and `Math.random` uses | These APIs are often non-security identifiers, cache keys or sampling; a security purpose must be established. |
| Generic or dynamically resolved cookie flags outside recognized session APIs | Framework defaults, reverse proxies, environment branches and cookie purpose change the correct conclusion. |
| Upload size/type policy | Limits and validation can live at middleware, edge, storage or application layers; one local syntax match is not enough. |
| Reflected dynamic CORS origin | Correct evaluation needs callback behavior, normalization and the actual origin allowlist data flow. |

These candidates remain suitable for agent-guided review or the mature SAST benchmark. They must
not be described as unavailable checks that passed.
