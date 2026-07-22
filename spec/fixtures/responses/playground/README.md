# Playground response fixtures

`accepted-live-2026-07-21.xml` was captured on 2026-07-21 by sending the official
public `CZ00000019.eet.v4.req.xml` sample byte-for-byte to the official Playground
endpoint over HTTP/1.1 with the documented SOAPAction. The HTTP response was 200 and
included an `X-Global-Transaction-ID`; headers and cookies are intentionally not
stored. The XML contains only public test identifiers, the public response signing
certificate, its XML signature, and a Playground POK ending in `-ff`. It contains no
private key, password, or production data.

The fixture's request UUID is `03965780-6457-4842-bd80-5f9195c0b8c8`. Its signature
verifies with both the strict Ruby verifier and `xmlsec1`. The embedded leaf builds to
the official I.CA chain pinned by the versioned Playground trust policy.

`unsigned-error.xml` is a deterministic local fixture matching the official XSD's
documented unsigned `Chyba` profile. It is not a captured server response and must
never be treated as authenticated evidence.
