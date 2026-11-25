# Requirements

Machine-readable source: [`requirements/catalog.json`](requirements/catalog.json).
The campaign fails if an in-scope id is missing from this file, from the catalog, or from a test.

Verification method for every in-scope row is an automated test (JUnit 5 or the C campaign), traced by requirement id into the HTML report.

## In scope

| ID | Level | Statement |
| --- | --- | --- |
| REQ-HSM-001 | functional | Unauthenticated `GET /api/v1/health` returns 200 with status UP, the lab token label, and a manufacturer string that identifies SoftHSM. |
| REQ-SEC-001 | security | A key or crypto call without the lab API key, or with the wrong key, is rejected with 401. The response does not echo the supplied key. Health stays open. |
| REQ-KEY-001 | functional | The API creates an AES-256 key as a token object, marked sensitive. The token refuses `CKA_VALUE`. The HTTP body is metadata only. |
| REQ-KEY-002 | functional | The API creates an RSA-2048 key pair on the token. The private key is sensitive. Reading `CKA_PRIVATE_EXPONENT` returns `CKR_ATTRIBUTE_SENSITIVE`. |
| REQ-KEY-003 | functional | The API creates a secp256r1 key pair on the token and reports that curve. |
| REQ-KEY-004 | functional | `GET /api/v1/keys` returns alias, algorithm, size, usage and sensitivity, and does not return key material. |
| REQ-KEY-005 | functional | `GET /api/v1/keys/{alias}` returns the metadata of a key that exists on the token. |
| REQ-KEY-006 | functional | `DELETE /api/v1/keys/{alias}` removes the object. A later lookup returns 404. |
| REQ-ENC-001 | functional | Ciphertext produced with a token AES key decrypts to the same plaintext. The IV is returned to the caller. |
| REQ-WRAP-001 | functional | An extractable AES key wrapped with `CKM_AES_KEY_WRAP` can be unwrapped under a new alias after the original is destroyed, and the restored key decrypts ciphertext from the original. |
| REQ-WRAP-002 | negative | Wrapping a key with `CKA_EXTRACTABLE=false` is rejected by the token. The API returns 400 and names the CKR. |
| REQ-WRAP-003 | functional | An extractable AES key can be wrapped with an RSA public key under `CKM_RSA_PKCS` and unwrapped with the matching private key, then used to decrypt. |
| REQ-SIG-001 | functional | A signature from the RSA private key (`CKM_SHA256_RSA_PKCS`) verifies with the matching public key. |
| REQ-SIG-002 | functional | A signature from the P-256 private key verifies with the matching public key. The token performs `CKM_ECDSA` over a SHA-256 digest. The signature is raw R\|\|S. |
| REQ-SIG-003 | negative | Flipping one byte of a valid signature makes verify report `valid=false`. |
| REQ-SIG-004 | negative | A signature from key A does not verify with key B of the same algorithm. |
| REQ-NEG-001 | negative | Lookup of an alias that is not on the token returns 404 `KEY_NOT_FOUND`. |
| REQ-NEG-002 | negative | The API returns 400 `MECHANISM_MISMATCH` when an RSA signature mechanism is asked of an AES key. The token itself also refuses that operation. |
| REQ-NEG-003 | negative | A user login with the wrong PIN returns `CKR_PIN_INCORRECT`. The lab session is restored afterwards and can still create a key. |
| REQ-NEG-004 | negative | Sign with an unknown alias returns 404 `KEY_NOT_FOUND`. |
| REQ-NEG-005 | negative | Creating a second key with an existing alias returns 409 `DUPLICATE_ALIAS` and leaves the original key in place. |
| REQ-NFR-001 | non-functional | Mean latency of five AES-256 generations stays under 2000 ms. Smoke budget, not a load test. |
| REQ-NFR-002 | non-functional | Mean latency of five SHA-256 RSA signatures stays under 2000 ms. Smoke budget, not a load test. |
| REQ-LOG-001 | negative | After a wrong-PIN probe and an authenticated call, the log contains the CKR name and the trace id, and does not contain the user PIN, the SO PIN, the lab API key, or the rejected PIN. |
| REQ-C-001 | native | A C program linked to SoftHSM opens a read-write session on the lab token and logs in. |
| REQ-C-002 | native | `C_GenerateKey` creates an AES-256 token key. Reading `CKA_VALUE` returns `CKR_ATTRIBUTE_SENSITIVE`. |
| REQ-C-003 | native | The C program encrypts and decrypts with `CKM_AES_CBC_PAD`. |
| REQ-C-004 | native | `C_Login` with a wrong user PIN, before any successful login in that process, returns `CKR_PIN_INCORRECT`. |
| REQ-C-005 | native | `C_DestroyObject` removes the campaign key. A search by label finds nothing. |
| REQ-TRC-001 | traceability | Each in-scope JUnit requirement has exactly one `@Requirement` test. Annotated ids exist in the catalog and in this file. |
| REQ-RPT-001 | report | Given a previous all-pass campaign and a current failure, the HTML report marks the campaign failed and names the regressed requirement. |

## Out of scope

| ID | Why it is listed |
| --- | --- |
| REQ-OOS-001 | FIPS 140-3 / Common Criteria boundary. SoftHSM2 is not a certified module. |
| REQ-OOS-002 | Thales ProtectServer mechanisms and vendor attributes. Not claimed here. |
| REQ-OOS-003 | Multi-token failover and clustering. |
| REQ-OOS-004 | mTLS, partition ACLs, identity provider. The lab API key is only a campaign control. |

Out-of-scope rows are printed on the report and are not failures.
