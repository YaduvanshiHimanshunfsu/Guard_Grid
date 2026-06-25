# crypto/ – Low-level cryptographic building blocks.
#
# This package contains the four mathematical primitives that the
# GuardGrid paper combines into its higher-level schemes:
#
#   dh.py           → Diffie-Hellman key agreement (Section III-D)
#   lhh.py          → Linear Homomorphic Hashing  (Section III-C)
#   mife_wrapper.py → Multi-Input Functional Encryption wrapper (Algo 1)
#   fefq.py         → Functional Encryption for Function Queries (Sec VI-B)
#
# Each file is self-contained: it imports only gmpy2 / hashlib / pymife,
# never another crypto module.  The only exception is lhh_setup() which
# reuses dh_params() to generate a safe prime, because the maths is
# identical — a safe prime with a QR-subgroup generator.
