use accumulator::group::Rsa2048;
use accumulator::Accumulator;
use rand::Rng;

#[test]
fn serde_test() {
    let mut acc_set = Vec::new();
    let mut acc = Accumulator::<Rsa2048, [u8; 32]>::empty();
    for _ in 0..100 {
        let random_elem = rand::thread_rng().gen::<[u8; 32]>();
        acc_set.push(random_elem);
    }
    acc = acc.clone().add(&acc_set);

    let new_elem = rand::thread_rng().gen::<[u8; 32]>();
    let (new_acc, add_proof) = acc.clone().add_with_proof(&[new_elem]);
    let deserialized_acc: Accumulator<Rsa2048, [u8; 32]> = {
        let serialized = serde_json::to_string(&new_acc).unwrap();
        println!("{}", serialized);
        serde_json::from_str(&serialized).unwrap()
    };
    let deserialized_add_proof = {
        let serialized = serde_json::to_string(&add_proof).unwrap();
        println!("{}", serialized);
        serde_json::from_str(&serialized).unwrap()
    };
    assert!(deserialized_acc.verify_membership(&new_elem, &deserialized_add_proof));

    let deserialized_delete_proof = {
        let (_, delete_proof) = deserialized_acc
            .clone()
            .delete_with_proof(&[(new_elem, add_proof.witness)])
            .unwrap();
        let serialized = serde_json::to_string(&delete_proof).unwrap();
        println!("{}", serialized);
        serde_json::from_str(&serialized).unwrap()
    };
    assert!(deserialized_acc.verify_membership(&new_elem, &deserialized_delete_proof));

    let deserialized_nonmem_proof = {
        let nonmem_proof = acc
            .prove_nonmembership(&acc_set, &[new_elem])
            .expect("It works");
        let serialized = serde_json::to_string(&nonmem_proof).unwrap();
        println!("{}", serialized);
        serde_json::from_str(&serialized).unwrap()
    };
    assert!(acc.verify_nonmembership(&[new_elem], &deserialized_nonmem_proof));
}
