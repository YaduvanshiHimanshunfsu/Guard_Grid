# schemes/ – Paper-level algorithms that compose crypto primitives.
#
# This package sits one abstraction layer above crypto/:
#
#   crypto/   → "here is how DH key agreement works"
#   schemes/  → "here is how the paper combines DH, LHH, and MIFE
#                into the FEHH aggregation protocol"
#
# Two modules:
#   fehh.py      → Algorithm 2 from the paper (FEHH scheme)
#   guardgrid.py → Section VI (full 4-phase GuardGrid protocol,
#                  adding FEFQ on top of FEHH)
