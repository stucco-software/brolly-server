# 0007 — Refuse RDF/XML on input

**Status:** Accepted (2026-08-18)
**Constrains:** Phase 4 (Solid content negotiation).

## Context

`cargo deny` surfaced two advisories against `quick-xml 0.37.5`:

- **RUSTSEC-2026-0194** — quadratic run time checking a start tag for duplicate
  attribute names.
- **RUSTSEC-2026-0195** — unbounded namespace-declaration allocation in
  `NsReader`, enabling memory-exhaustion denial of service.

Both are denial-of-service class, and both are reachable from **untrusted
federation input** if we parse RDF/XML from the network. That is a materially
worse posture than the `rsa` advisory in ADR 0003, which needs an attacker able
to finely time private-key operations.

The dependency cannot be removed or updated:

- `quick-xml 0.37.5` is the newest release in the `0.37` line, pinned by
  `oxrdfxml 0.2.3` ← `oxrdfio 0.2.5` ← `oxigraph 0.5.9`. `quick-xml 0.41` exists
  but oxigraph does not accept it.
- RDF/XML is **not** an optional oxigraph feature. `oxrdfxml` is an
  unconditional dependency of `oxrdfio`, so there is no feature flag to turn
  off.

## Decision

**Never parse RDF/XML from network input.** The vulnerable code stays in the
binary; it becomes unreachable from untrusted data.

Concretely, in Phase 4:

- Content negotiation **may** offer `application/rdf+xml` on read (serialization
  is not affected by either advisory).
- Write paths — LDP `PUT`, `POST`, `PATCH`, ActivityPub inbox, anything parsing
  a request body — reject `Content-Type: application/rdf+xml` with `415
  Unsupported Media Type`.
- A test asserts the rejection, so the mitigation cannot silently regress when
  someone extends the parser table.

RDF/XML is the least-used RDF serialization on the wire; Turtle, N-Triples,
N-Quads, and JSON-LD cover every real client. The cost of refusing it is close
to zero and the attack surface removed is real.

## Consequences

- The two advisories are recorded as justified `ignore` entries in `deny.toml`
  **paired with this mitigation**, not waved through. Ignoring an advisory whose
  attack path we had left open would be dishonest.
- Phase 4 carries a concrete deliverable and a test rather than a footnote.
- If oxigraph later accepts a fixed `quick-xml`, drop both ignores and
  reconsider accepting RDF/XML on input. Review trigger: any oxigraph bump.
- A Solid client that can *only* send RDF/XML cannot write to us. No such client
  is known, and it would be an odd one.
