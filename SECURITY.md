# Security policy

This project processes signing credentials and verifies signed government protocol
responses. Treat credential exposure, signature bypass, trust-policy bypass,
signature wrapping, XML external-entity processing, unexpected network access,
automatic retry, and acceptance of an unverified POK as security issues.

## Supported versions

No released version is currently supported. Security support will start with the
first published pre-1.0 release and will be listed here explicitly.

## Reporting

Do not disclose a suspected vulnerability in a public issue. Until the repository
owner enables private vulnerability reporting and records a security contact, share
details directly with the project owner through an established private channel.

Include the affected version or commit, Ruby/OpenSSL/Nokogiri versions, a minimal
reproducer without real credentials, expected impact, and whether the issue can
accept a forged or untrusted EET acceptance.

Never attach production PKCS#12/PFX files, passwords, private keys, or raw production
payloads to a report.
