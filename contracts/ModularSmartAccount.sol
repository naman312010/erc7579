// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../interfaces/IERC7579Account.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "../interfaces/IERC7579Module.sol";
import {ModuleManager} from "./ModuleManager.sol";
import "./ExecutionHelper.sol";
import "../lib/ModeLib.sol";
import {ExecutionLib} from "../lib/ExecutionLib.sol";
import {SentinelListLib, SENTINEL} from "@rhinestone/sentinellist/src/SentinelList.sol";
import { ECDSA } from "solady/src/utils/ECDSA.sol";

contract ModularSmartAccount is
    Initializable,
    IERC7579Account,
    ModuleManager,
    ExecutionHelper
{


    // Error thrown when an unsupported ModuleType is requested
    error UnsupportedModuleType(uint256 moduleTypeId);
    // Error thrown when an execution with an unsupported CallType was made
    error UnsupportedCallType(CallType callType);
    // Error thrown when an execution with an unsupported ExecType was made
    error UnsupportedExecType(ExecType execType);
    // Error thrown when account initialization fails
    error AccountInitializationFailed();
    // Error thrown when account installs/unistalls module with mismatched input `moduleTypeId`
    error MismatchModuleTypeId(uint256 moduleTypeId);

    using ModeLib for ModeCode;
    using ExecutionLib for bytes;
    using ECDSA for bytes32;

    using SentinelListLib for SentinelListLib.SentinelList;

    /**
     * @dev Initializes the account. Function might be called directly, or by a Factory
     * @param data. encoded data that can be used during the initialization phase
     */
    function initializeAccount(bytes calldata data) public payable virtual initializer {
        // protect this function to only be callable when used with the proxy factory or when
        // account calls itself
        if (msg.sender != address(this)) {
            checkInitializable();
        }

        // checks if already initialized and reverts before setting the state to initialized
        _initModuleManager();

        // bootstrap the account
        (address bootstrap, bytes memory bootstrapCall) = abi.decode(data, (address, bytes));
        _initAccount(bootstrap, bootstrapCall);
    }

    /**
     * @dev Bootstrap function to initialize the account
     * @param bootstrap. address of the bootstrap contract,
     * @param bootstrapCall. encoded data that can be used during the initialization phase
     */
    function _initAccount(address bootstrap, bytes memory bootstrapCall) private {
        // this is just implemented for demonstration purposes. You can use any other initialization
        // logic here.
        (bool success,) = bootstrap.delegatecall(bootstrapCall);
        if (!success) revert();
    }

    bytes32 constant INIT_SLOT = keccak256(
    abi.encode(uint256(keccak256("initializable.transient.msa")) - 1)
) & ~bytes32(uint256(0xff));

    function checkInitializable() internal view {
        bytes32 slot = INIT_SLOT;
        // Load the current value from the slot, revert if 0
        assembly {
            let isInitializable := sload(slot)
            if iszero(isInitializable) {
                mstore(0x0, 0xaed59595) // NotInitializable()
                revert(0x1c, 0x04)
            }
        }
    }

    /**
     * @dev Executes a transaction on behalf of the account.
     *         This function is intended to be called by ERC-4337 EntryPoint.sol
     * @dev MSA MUST implement this function signature.
     * If a mode is requested that is not supported by the Account, it MUST revert
     * @param mode The encoded execution mode of the transaction. See ModeLib.sol for details
     * @param executionCalldata The encoded execution call data
     */
    function execute(
        ModeCode mode,
        bytes calldata executionCalldata
    ) external payable onlyEntryPointOrSelf {
        (CallType callType, ExecType execType, , ) = mode.decode();

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = executionCalldata.decodeBatch();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) _execute(executions);
            else if (execType == EXECTYPE_TRY) _tryExecute(executions);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (
                address target,
                uint256 value,
                bytes calldata callData
            ) = executionCalldata.decodeSingle();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT)
                _execute(target, value, callData);
                // TODO: implement event emission for tryExecute singleCall
            else if (execType == EXECTYPE_TRY)
                _tryExecute(target, value, callData);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_DELEGATECALL) {
            // destructure executionCallData according to single exec
            address delegate = address(
                uint160(bytes20(executionCalldata[0:20]))
            );
            bytes calldata callData = executionCalldata[20:];
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT)
                _executeDelegatecall(delegate, callData);
            else if (execType == EXECTYPE_TRY)
                _tryExecuteDelegatecall(delegate, callData);
            else revert UnsupportedExecType(execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    

    /**
     * @dev Executes a transaction on behalf of the account.
     *         This function is intended to be called by Executor Modules
     * @dev Ensure adequate authorization control: i.e. onlyExecutorModule
     *
     * @dev MSA MUST implement this function signature.
     * If a mode is requested that is not supported by the Account, it MUST revert
     * @param mode The encoded execution mode of the transaction. See ModeLib.sol for details
     * @param executionCalldata The encoded execution call data
     */
    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    ) external payable onlyExecutorModule returns (bytes[] memory returnData) {
        (CallType callType, ExecType execType, , ) = mode.decode();

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = executionCalldata.decodeBatch();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) returnData = _execute(executions);
            else if (execType == EXECTYPE_TRY)
                returnData = _tryExecute(executions);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (
                address target,
                uint256 value,
                bytes calldata callData
            ) = executionCalldata.decodeSingle();
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) {
                returnData[0] = _execute(target, value, callData);
            }
            // TODO: implement event emission for tryExecute singleCall
            else if (execType == EXECTYPE_TRY) {
                (success, returnData[0]) = _tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert UnsupportedExecType(execType);
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            // destructure executionCallData according to single exec
            address delegate = address(
                uint160(bytes20(executionCalldata[0:20]))
            );
            bytes calldata callData = executionCalldata[20:];
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT)
                _executeDelegatecall(delegate, callData);
            else if (execType == EXECTYPE_TRY)
                _tryExecuteDelegatecall(delegate, callData);
            else revert UnsupportedExecType(execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    /**
     * @dev ERC-1271 isValidSignature
     *         This function is intended to be used to validate a smart account signature
     * and may forward the call to a validator module
     *
     * @param hash The hash of the data that is signed
     * @param data The data that is signed
     */
    function isValidSignature(
        bytes32 hash,
        bytes calldata data
    ) external view returns (bytes4) {
        address validator = address(bytes20(data[0:20]));
        if (!_isValidatorInstalled(validator)) revert InvalidModule(validator);
        return
            IValidator(validator).isValidSignatureWithSender(
                msg.sender,
                hash,
                data[20:]
            );
    }

    function validateUserOp(
        PackedUserOperation memory userOp,
        bytes32 userOpHash
    )
        external
        payable
        onlyEntryPoint
        returns (uint256 validSignature)
    {
        address validator;
        // @notice validator encoding in nonce is just an example!
        // @notice this is not part of the standard!
        // Account Vendors may choose any other way to implement validator selection
        uint256 nonce = userOp.nonce;
        assembly {
            validator := shr(96, nonce)
        }

        // check if validator is enabled. If not terminate the validation phase.
        if (!_isValidatorInstalled(validator)) {
            revert("VALIDATOR_MODULE_NOT_INSTALLED");
        } else {
            // bubble up the return value of the validator module
            validSignature = IValidator(validator).validateUserOp(userOp, userOpHash);
        }
    }

    /**
     * @dev installs a Module of a certain type on the smart account
     * @dev Implement Authorization control of your chosing
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     * @param module the module address
     * @param initData arbitrary data that may be required on the module during `onInstall`
     * initialization.
     */
    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    ) external payable {
        if (!IModule(module).isModuleType(moduleTypeId))
            revert MismatchModuleTypeId(moduleTypeId);

        if (moduleTypeId == MODULE_TYPE_VALIDATOR)
            _installValidator(module, initData);
        else if (moduleTypeId == MODULE_TYPE_EXECUTOR)
            _installExecutor(module, initData);
        else if (moduleTypeId == MODULE_TYPE_FALLBACK)
            _installFallbackHandler(module, initData);
        else revert UnsupportedModuleType(moduleTypeId);
        emit ModuleInstalled(moduleTypeId, module);
    }

    /**
     * @dev uninstalls a Module of a certain type on the smart account
     * @dev Implement Authorization control of your chosing
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     * @param module the module address
     * @param deInitData arbitrary data that may be required on the module during `onUninstall`
     * de-initialization.
     */
    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    ) external payable {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            _uninstallValidator(module, deInitData);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            _uninstallExecutor(module, deInitData);
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            _uninstallFallbackHandler(module, deInitData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /**
     * Function to check if the account supports a certain CallType or ExecType (see ModeLib.sol)
     * @param mode the encoded mode
     */
    function supportsExecutionMode(
        ModeCode mode
    ) external pure returns (bool isSupported) {
        (CallType callType, ExecType execType, , ) = mode.decode();
        if (callType == CALLTYPE_BATCH) isSupported = true;
        else if (callType == CALLTYPE_SINGLE) isSupported = true;
        else if (callType == CALLTYPE_DELEGATECALL)
            isSupported = true;
            // if callType is not single, batch or delegatecall return false
        else return false;

        if (execType == EXECTYPE_DEFAULT) isSupported = true;
        else if (execType == EXECTYPE_TRY)
            isSupported = true;
            // if execType is not default or try, return false
        else return false;
    }

    /**
     * Function to check if the account supports installation of a certain module type Id
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     */
    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) return true;
        else if (moduleTypeId == MODULE_TYPE_EXECUTOR) return true;
        else if (moduleTypeId == MODULE_TYPE_FALLBACK) return true;
        else return false;
    }

    /**
     * Function to check if the account has a certain module installed
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *      Note: keep in mind that some contracts can be multiple module types at the same time. It
     *            thus may be necessary to query multiple module types
     * @param module the module address
     * @param additionalContext additional context data that the smart account may interpret to
     *                          identifiy conditions under which the module is installed.
     *                          usually this is not necessary, but for some special hooks that
     *                          are stored in mappings, this param might be needed
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) external view returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            return _isValidatorInstalled(module);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return _isExecutorInstalled(module);
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            return
                _isFallbackHandlerInstalled(
                    abi.decode(additionalContext, (bytes4)),
                    module
                );
        } else {
            return false;
        }
    }

    /**
     * @dev Returns the account id of the smart account
     * @return accountImplementationId the account id of the smart account
     * the accountId should be structured like so:
     *        "vendorname.accountname.semver"
     */
    function accountId()
        external
        pure
        returns (string memory accountImplementationId)
    {
        {
            return "simple.msa";
        }
    }

    
}
