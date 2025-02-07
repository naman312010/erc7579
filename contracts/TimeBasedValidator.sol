// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../interfaces/IERC7579Account.sol";
import "../interfaces/IERC7579Module.sol";
import "../lib/ModeLib.sol";
import "../lib/ExecutionLib.sol";
import "./AccountBase.sol";
import {ECDSA} from "solady/src/utils/ECDSA.sol";
import "./ModularSmartAccount.sol";

contract TimeBasedValidator is IValidator, AccountBase {
    using ExecutionLib for bytes;
    using ECDSA for bytes32;

    error InvalidExec();

    mapping(address => bool) internal _initialized;
    mapping(address => uint) internal _lastTxnTimestamp;

    function onInstall(
        bytes calldata // data
    ) external override {
        if (isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        _initialized[msg.sender] = true;
    }

    function onUninstall(
        bytes calldata // data
    ) external override {
        if (!isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        _initialized[msg.sender] = false;
    }

    function isInitialized(
        address smartAccount
    ) public view override returns (bool) {
        return _initialized[smartAccount];
    }

    function isModuleType(
        uint256 moduleTypeId
    ) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function _checkThreeMins(address sender) internal view returns (bool) {
        if (
            _lastTxnTimestamp[sender] == 0 ||
            (block.timestamp - _lastTxnTimestamp[sender]) >= 3 minutes
        ) return true;
        else return false;
    }

    function _updateLastTxn(address sender) internal {
        _lastTxnTimestamp[sender] = block.timestamp;
    }

// made only callable by a modular smart account
    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        require(isInitialized(msg.sender), "Smart account not initialized");

        require(_checkThreeMins(userOp.sender), "3MINSERROR: Please wait atleast 3 minutes before making another transaction");

        address signer = ECDSA.recover(
            userOpHash.toEthSignedMessageHash(),
            userOp.signature
        );

        if (signer != userOp.sender) {
            return VALIDATION_FAILED;
        }
        _updateLastTxn(userOp.sender);
        return VALIDATION_SUCCESS;
    }

    function recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);

        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

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

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        bytes4 magic = 0x1626ba7e;
        require(recoverSigner(hash, signature) == sender, "INVALID_SIGNATURE");
        return magic;
    }
}
