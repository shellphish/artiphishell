(declare-fun k!0 () (_ BitVec 8))
(declare-fun k!10 () (_ BitVec 8))
(assert (= k!0 #xff))
(assert (not (= k!10 #xff)))
(assert (not (= k!10 #xd8)))
(assert (= k!0 #x53))

(check-sat)