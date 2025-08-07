(declare-fun k!0 () (_ BitVec 8))
(assert (= (ite false k!0 #x00) #x00))
(check-sat)
