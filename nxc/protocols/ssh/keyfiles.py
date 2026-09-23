
# Substrings paramiko raises when the server refuses a public key whose algorithm is not in its accepted list, e.g. sshd set to "PubkeyAcceptedAlgorithms ssh-ed25519" while the key is RSA.
# They must be told apart from a wrong passphrase, otherwise the operator gets an error pointing at the wrong thing.
KEY_TYPE_REJECTED_SUBSTRINGS = (
    "no RSA pubkey algorithms are configured",
    "Unable to agree on a pubkey algorithm",
)


def is_key_type_rejected(exc):
    """Return True if exc means the server rejected the key's algorithm."""
    return any(sub in str(exc) for sub in KEY_TYPE_REJECTED_SUBSTRINGS)
