// audit-core: Authorised actor check
// Proves: actor hash is in the approved set
// allowed_hashes is public so auditor sees the policy
// actor_hash is private so identity stays off-chain

fn main(
    actor_hash: Field,               // private: sha256 of actor ARN mod BN254
    allowed_hashes: pub [Field; 8],  // public: approved actors (padded with 0)
) -> pub bool {
    let mut found = false;
    for i in 0..8 {
        if allowed_hashes[i] == actor_hash {
            found = true;
        }
    }
    assert(found);
    found
}
