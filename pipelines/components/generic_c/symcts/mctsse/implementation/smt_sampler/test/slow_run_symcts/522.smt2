(declare-fun k!0 () (_ BitVec 8))
(assert (= k!0 #xff))
(assert (not (= k!0 #xff)))

(check-sat)