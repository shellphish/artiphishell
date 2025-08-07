(declare-fun k!0 () (_ BitVec 8))
(declare-fun k!10 () (_ BitVec 8))
(assert (= k!0 #xff))
(assert (not (= k!10 #xff)))
(assert (not (= k!10 #xd8)))
(assert (bvsle (concat #x000000 k!10) #x00000001))
(assert (not (= k!10 #x01)))

(check-sat)