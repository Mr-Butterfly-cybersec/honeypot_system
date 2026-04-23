// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract HoneypotAuditLog {
    struct SecurityEvent {
        bytes32 eventId;
        bytes32 eventHash;
        bytes32 previousHash;
        bytes32 ipHash;
        uint8 severity;
        uint256 timestamp;
    }

    address public owner;
    SecurityEvent[] private events;

    event TrapEventAnchored(
        bytes32 indexed eventId,
        bytes32 indexed eventHash,
        uint8 severity,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function logEvent(
        bytes32 eventId,
        bytes32 eventHash,
        bytes32 previousHash,
        bytes32 ipHash,
        uint8 severity
    ) external onlyOwner {
        events.push(
            SecurityEvent({
                eventId: eventId,
                eventHash: eventHash,
                previousHash: previousHash,
                ipHash: ipHash,
                severity: severity,
                timestamp: block.timestamp
            })
        );

        emit TrapEventAnchored(eventId, eventHash, severity, block.timestamp);
    }

    function getEventCount() external view returns (uint256) {
        return events.length;
    }

    function getEvent(uint256 index) external view returns (SecurityEvent memory) {
        require(index < events.length, "Index out of range");
        return events[index];
    }
}
