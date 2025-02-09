// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../interfaces/IERC7579Account.sol";
import "../interfaces/IERC7579Module.sol";
import "../lib/ModeLib.sol";
import "../lib/ExecutionLib.sol";
import {ECDSA} from "solady/src/utils/ECDSA.sol";
import "./ModularSmartAccount.sol";

contract TimeBasedValidator is IValidator {
    using ExecutionLib for bytes;
    using ECDSA for bytes32;

    // which addresses initialized to
    mapping(address => bool) internal _initialized;
    //timestamp management for various acounts
    mapping(address => uint) internal _lastTxnTimestamp;

    /**
     * @dev executes call data to install the module
     * @param data just kept it as per standard, as some stuff can be encoded
     */
    function onInstall(bytes calldata data) external override {
        if (isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        _initialized[msg.sender] = true;
    }

    /**
     * @dev executes call data to uninstall the module
     * @param data just kept it as per standard, as some stuff can be encoded
     */
    function onUninstall(bytes calldata data) external override {
        if (!isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        _initialized[msg.sender] = false;
    }

    /**
     * @dev checks if account is initialized to work with the smart account
     * @param smartAccount smart account address
     */
    function isInitialized(
        address smartAccount
    ) public view override returns (bool) {
        return _initialized[smartAccount];
    }

    /**
     * @dev returns true of a module is of the given type
     * @param moduleTypeId module type id to be cheched
     */
    function isModuleType(
        uint256 moduleTypeId
    ) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /**
     * @dev returns the TypeId of the module
     */
    function getModuleType() external pure returns (uint256) {
        return MODULE_TYPE_VALIDATOR;
    }

    /**
     * @dev checks if 3 minutes have passed since the last recorded transaction for a sender
     * @param sender sender address
     */
    function _checkThreeMins(address sender) internal view returns (bool) {
        if (
            _lastTxnTimestamp[sender] == 0 ||
            (block.timestamp - _lastTxnTimestamp[sender]) >= 3 minutes
        ) return true;
        else return false;
    }

    /**
     * @dev updates the last recorded transaction for a sender
     * @param sender sender address
     */
    function _updateLastTxn(address sender) internal {
        _lastTxnTimestamp[sender] = block.timestamp;
    }

    /**
     * @dev Validates a UserOperation
     * @param userOp the ERC-4337 PackedUserOperation
     * @param userOpHash the hash of the ERC-4337 PackedUserOperation
     *
     * @notice MUST validate that the signature is a valid signature of the userOpHash
     * @notice SHOULD return ERC-4337's SIG_VALIDATION_FAILED (and not revert) on signature mismatch
     * @notice made only callable by a modular smart account
     */
    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        require(isInitialized(msg.sender), "Smart account not initialized");

        require(
            _checkThreeMins(userOp.sender),
            "3MINSERROR: Please wait atleast 3 minutes before making another transaction"
        );

        address signer = ECDSA.recover(
            userOpHash.toEthSignedMessageHash(),
            userOp.signature
        );

        if (signer != userOp.sender) {
            return VALIDATION_FAILED;
        }
        // Only update timestamp when it's an actual transaction
        if (tx.origin != address(0)) {
            _updateLastTxn(userOp.sender);
        }
        return VALIDATION_SUCCESS;
    }

    /**
     * @dev recovers signer from signed message hash and signature
     * @param _ethSignedMessageHash signed message hash
     * @param _signature signature to be verified
     */
    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    /**
     * @dev Good ol' signature splitter function. never wrote myself by hand
     * @param sig signature to be split
     */
    function splitSignature(
        bytes memory sig
    ) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            /*
            First 32 bytes stores the length of the signature

            add(sig, 32) = pointer of sig + 32
            effectively, skips first 32 bytes of signature

            mload(p) loads next 32 bytes starting at the memory address p into memory
            */

            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        // implicitly returning (r, s, v)
    }

    /**
     * @dev Checks if signature is valid for the alleged signer and given message
     * @param sender sender address
     * @param hash signed message hash
     * @param signature user signature
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external pure override returns (bytes4) {
        bytes4 magic = 0x1626ba7e;
        require(recoverSigner(hash, signature) == sender, "INVALID_SIGNATURE");
        return magic;
    }
}
