// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EIP712Utils
/// @notice Shared EIP-712 utilities for ShieldNode settlement contracts.
///         Extracted to ensure RECEIPT_TYPEHASH and signature recovery are
///         defined in exactly one place.
library EIP712Utils {
    /// @notice The EIP-712 typehash for bandwidth receipts.
    ///         Used by SessionSettlement, ZKSettlement, and SlashingOracle.
    bytes32 internal constant RECEIPT_TYPEHASH = keccak256(
        "BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)"
    );

    /// @notice Compute the EIP-712 struct hash for a bandwidth receipt.
    function receiptStructHash(
        uint256 sessionId,
        uint256 cumulativeBytes,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(RECEIPT_TYPEHASH, sessionId, cumulativeBytes, timestamp)
        );
    }

    /// @notice Compute the full EIP-712 digest.
    function hashTypedData(
        bytes32 domainSeparator,
        bytes32 structHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice Recover the signer of an ECDSA signature.
    /// @param digest The EIP-712 digest that was signed.
    /// @param sig    The 65-byte signature (r || s || v).
    function recoverSigner(
        bytes32 digest,
        bytes memory sig
    ) internal pure returns (address) {
        require(sig.length == 65, "EIP712: bad sig length");
        bytes32 r;
        bytes32 s_;
        uint8 v;
        assembly {
            r  := mload(add(sig, 32))
            s_ := mload(add(sig, 64))
            v  := byte(0, mload(add(sig, 96)))
        }
        address signer = ecrecover(digest, v, r, s_);
        require(signer != address(0), "EIP712: invalid sig");
        return signer;
    }
}
