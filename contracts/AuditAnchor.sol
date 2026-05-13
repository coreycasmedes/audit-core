// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Verifier.sol";

// audit-core: Immutable ZK proof registry for AWS admin actions.
// No PII on chain — only proof hashes and non-sensitive metadata.
// Each eventId can only be anchored once.

contract AuditAnchor {

    struct Record {
        bytes32 proofHash;    // keccak256 of raw proof bytes
        bool    passed;       // did all policy checks pass?
        uint64  timestamp;    // unix seconds of the original AWS event
        uint64  anchoredAt;   // block.timestamp when anchored
        uint64  blockNumber;  // block.number when anchored
        string  eventType;    // e.g. "ConsoleLogin"
        string  circuitSet;   // e.g. "mfa_check,hours_check,role_check"
    }

    mapping(bytes32 => Record) public records;
    bytes32[] public eventIndex;

    Verifier public immutable verifier;

    event ProofAnchored(
        bytes32 indexed eventId,
        bytes32         proofHash,
        bool            passed,
        uint64          timestamp,
        string          eventType
    );

    event PolicyViolation(
        bytes32 indexed eventId,
        string          eventType,
        uint64          timestamp
    );

    constructor(address _verifier) {
        verifier = Verifier(_verifier);
    }

    function anchorProof(
        bytes32          eventId,
        bytes   calldata proof,
        bytes32[] calldata publicInputs,
        bool             passed,
        uint64           timestamp,
        string  calldata eventType,
        string  calldata circuitSet
    ) external {
        require(records[eventId].anchoredAt == 0, "Already anchored");

        bool proofValid = verifier.verify(proof, publicInputs);
        require(proofValid || !passed, "Invalid proof for passing claim");

        bytes32 proofHash = keccak256(proof);

        records[eventId] = Record({
            proofHash:   proofHash,
            passed:      passed,
            timestamp:   timestamp,
            anchoredAt:  uint64(block.timestamp),
            blockNumber: uint64(block.number),
            eventType:   eventType,
            circuitSet:  circuitSet
        });

        eventIndex.push(eventId);

        emit ProofAnchored(eventId, proofHash, passed, timestamp, eventType);

        if (!passed) {
            emit PolicyViolation(eventId, eventType, timestamp);
        }
    }

    function getRecord(bytes32 eventId) external view returns (Record memory) {
        return records[eventId];
    }

    function getTotalAnchored() external view returns (uint256) {
        return eventIndex.length;
    }

    function getRecentEvents(uint256 count) external view returns (bytes32[] memory) {
        uint256 len = eventIndex.length;
        uint256 n   = count > len ? len : count;
        bytes32[] memory recent = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            recent[i] = eventIndex[len - n + i];
        }
        return recent;
    }
}
