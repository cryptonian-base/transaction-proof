** Prover 는 1. 머클 트리 루트 root, 2. 특정 리프 leaf, 3. 머클 패쓰 (root에서 leaf까지),  4. 해시 값 prev_leaf ( = sha256(leaf)) 을 알고 있다.

** Verifier 는 1. 머클 트리 루트 root 2. 해시값 prev_leaf 만 알고 있다. Verifier는 zkSNARK proof 를 통해 Prover가 1. prev_leaf 의 원본과 2. root-leaf 의 머클 패쓰를 알고있음을 검증할 수 있다.

** 실행은 ./get-libsnark && make && ./main 으로 한다. 

** Merkle Tree 의 depth를 수정하기 위해서는  src/gadget.hpp 의 line 4 에서 tree_depth 를 수정하고 make && ./main 하면 된다.