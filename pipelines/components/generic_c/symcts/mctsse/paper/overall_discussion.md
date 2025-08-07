# Symsan

We did all of this without symsan's performance optimizations.
They are orthogonal to our work and can be applied to our work as well to improve performance.
However, as noted in the discussion, concolic tracing is not the performance bottleneck anymore.
Improvements to solving and coverage tracing are strictly more important.
As such, we can borrow heavily from all of the existing research into coverage tracing performance in the
fuzzing community.

# Applicability