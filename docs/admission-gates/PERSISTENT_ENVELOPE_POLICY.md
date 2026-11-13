# Experimental bounded-persistence envelope

`PersistentEnvelopePolicy` preserves the original retreat/global channels and
adds K consecutive supported, positive individual-envelope observations as a
peak-independent proposal. K is one of 2, 3, 4. This provides a conditional
confirmation bound and retains mandatory rejection, prefix ordering, exact
retries, review-only accumulated evidence and quorum bookkeeping.

All three development candidates failed the declared no-false-currently-clean
proposal criterion. The class is retained for reproducible experiments and unit
checks; it is not used by `live-client-envelope-retreat-v1`. The live profile
continues to use `ClientEnvelopePolicy`. See
[the validation report](LIVE_ENVELOPE_VALIDATION.md) for the real adaptive
counterexample, the development failure and the actual live integration scope.
