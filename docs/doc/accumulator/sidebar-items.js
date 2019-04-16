initSidebarItems({"enum":[["AccError","The different types of accumulator errors."],["VCError","The different types of vector commitment errors."]],"mod":[["group","Implementations for different mathematical groups, each of which satisfies our `UnknownOrderGroup` trait. They can be used with the accumulator and vector commitment structures, or standalone if you have a custom application."],["hash","This module wraps `blake2b_rfc` into a convenient hashing interface (`GeneralHasher`) and exports the generalized `hash` function. Also exported is `hash_to_prime`, which works by primality-testing the iterative outputs of `hash`."],["proof","Succinct proofs over unknown-order groups. These proofs are used as building blocks for many of the cryptographic primitives in this library."],["uint","Zero-allocation U256 and U512 types built on GMP. We created this module specifically for our use case of implementing primality checking over 256-bit integers, but it may be worth polishing a bit for more general use."],["util","Miscellaneous functions used throughout the library."]],"struct":[["Accumulator","A cryptographic accumulator. Wraps a single unknown-order group element and phantom data representing the type `T` being hashed-to-prime and accumulated."],["MembershipProof","A succinct proof of membership (some element is in some accumulator)."],["NonmembershipProof","A succinct proof of nonmembership (some element is not in some accumulator)."],["VectorCommitment","A vector commitment, wrapping an underlying accumulator. The accumulator contains indices of an abstract vector where the corresponding bit is True."],["VectorProof","A vector commitment proof."],["Witness","A witness to one or more values in an accumulator, represented as an accumulator."]]});