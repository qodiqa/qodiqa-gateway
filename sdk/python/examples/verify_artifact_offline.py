"""QODIQA SDK — Local (offline) artifact verification example.

Demonstrates verifying a signed artifact's Ed25519 signature, canonical
JSON, and key validity entirely on the client — WITHOUT ever calling the
server's `/verify` endpoint or trusting its response.

Run:
    QODIQA_SIGN_TOKEN=<token> QODIQA_BASE_URL=http://localhost:3000 python examples/verify_artifact_offline.py
"""

import os

from qodiqa import ArtifactVerifier, QodiqaClient, RemoteKeyProvider

BASE_URL = os.environ.get("QODIQA_BASE_URL", "http://localhost:3000")


def main() -> None:
    client = QodiqaClient(sign_token=os.environ.get("QODIQA_SIGN_TOKEN"), base_url=BASE_URL)

    # 1. Obtain a signed artifact the normal way (server-side signing is not
    #    part of this remediation — only verification moves client-side).
    signed = client.sign.sign(
        {
            "request": {"method": "POST", "path": "/ai/chat", "body": {"prompt": "Hello"}},
            "payload": {"userId": "user_123"},
            "ttl": 300_000,
        }
    )

    # 2. Configure two SEPARATE key providers — one for artifact-signing keys,
    #    one for transparency-signing keys. These are cryptographically
    #    distinct trust domains server-side; never point both at the same
    #    source, or that separation is silently defeated.
    artifact_keys = RemoteKeyProvider(discovery_url=f"{BASE_URL}/.well-known/qodiqa/keys")
    transparency_keys = RemoteKeyProvider(discovery_url=f"{BASE_URL}/.well-known/qodiqa/transparency-keys")

    verifier = ArtifactVerifier(keys=artifact_keys, transparency_keys=transparency_keys)

    # 3. Verify entirely locally. No network call happens here beyond the
    #    one-time (cached) key-list fetch above.
    result = verifier.verify(signed["artifact"])

    print("\n--- Local verification result ---")
    print("verification_status:  ", result.verification_status)
    print("signature_valid:      ", result.signature_valid)
    print("canonicalization_valid:", result.canonicalization_valid)
    print("key_valid:            ", result.key_valid, f"({result.key_id}, {result.key_status})")
    print("timestamp_valid:      ", result.timestamp_valid)
    print("expiry_valid:         ", result.expiry_valid)
    print("transparency_verified:", result.transparency_verified)  # 'unavailable' — no proof supplied above

    if result.verification_status != "valid":
        print("failed_stage: ", result.failed_stage)
        print("errors:       ", result.verification_errors)
        client.close()
        return

    # 4. Optional: fetch and locally verify a transparency inclusion proof for
    #    an artifact already registered in the transparency log.
    #
    # proof = client.transparency.get_proof(some_transparency_id)["data"]["proof"]
    # result_with_proof = verifier.verify(signed["artifact"], transparency_proof=proof)
    # print("transparency_verified:", result_with_proof.transparency_verified)  # 'verified' | 'failed'

    artifact_keys.close()
    transparency_keys.close()
    client.close()


if __name__ == "__main__":
    main()
