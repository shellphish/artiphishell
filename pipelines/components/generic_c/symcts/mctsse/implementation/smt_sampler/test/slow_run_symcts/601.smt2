(declare-fun k!0 () (_ BitVec 8))
(declare-fun k!10 () (_ BitVec 8))
(assert (= k!0 #xff))
(assert (not (= k!10 #xff)))
(assert (not (= k!10 #xd8)))
(assert (and (= k!0 #x50) (= ((_ extract 7 7) k!0) #b0)))

(check-sat)