// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EIP712Utils
/// @notice Shared EIP-712 utilities for ShieldNode settlement contracts.
///         Extracted to ensure RECEIPT_TYPEHASH and signature recovery are
///         defined in exactly one place.
library EIP712Utils {
    // ── Errors ────────────────────────────────────────────────────

    error BadSignatureLength(uint256 length);
    error InvalidSignature();

    /// @notice The EIP-712 typehash for bandwidth receipts.
    ///         Used by SessionSettlement, ZKSettlement, and SlashingOracle.
    bytes32 internal constant RECEIPT_TYPEHASH = keccak256(
        "BandwidthReceipt(uint256 sessionId,uint256 cumulativeBytes,uint256 timestamp)"
    );

    /// @notice Compute the EIP-712 domain separator for a ShieldNode contract.
    /// @param contractAddr The verifyingContract address (typically address(this)).
    function computeDomainSeparator(address contractAddr) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ShieldNode"),
                keccak256("1"),
                block.chainid,
                contractAddr
            )
        );
    }

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

    /// @dev Upper bound for `s` value (EIP-2 malleability protection).
    uint256 private constant SECP256K1N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @notice Recover the signer of an ECDSA signature.
    /// @param digest The EIP-712 digest that was signed.
    /// @param sig    The 65-byte signature (r || s || v).
    function recoverSigner(
        bytes32 digest,
        bytes memory sig
    ) internal pure returns (address) {
        if (sig.length != 65) revert BadSignatureLength(sig.length);
        bytes32 r;
        bytes32 s_;
        uint8 v;
        assembly {
            r  := mload(add(sig, 32))
            s_ := mload(add(sig, 64))
            v  := byte(0, mload(add(sig, 96)))
        }
        require(uint256(s_) <= SECP256K1N_HALF, "EIP712Utils: malleable sig");
        address signer = ecrecover(digest, v, r, s_);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
}
