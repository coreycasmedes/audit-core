// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// audit-core: Stub verifier for POC
// TODO: Replace with bb codegen output for production.
// Run: bb write_vk + generate a Solidity verifier from the UltraHonk VK.
// This stub accepts any non-zero proof of non-zero length.

contract Verifier {
    function verify(
        bytes calldata proof,
        bytes32[] calldata publicInputs
    ) external pure returns (bool) {
        if (proof.length == 0) return false;
        if (keccak256(proof) == bytes32(0)) return false;
        return true;
    }
}
