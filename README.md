# ERC7579 minimum implementation (WIP)

An attempt to implement upgradeable modular smart accounts based on ERC7579

Untested, lacking documentation and based on [ERC7579 reference implementation](https://github.com/erc7579/erc7579-implementation)

TODO:

Figure out validator encoding:

```
    address validator;
    // @notice validator encoding in nonce is just an example!
    // @notice this is not part of the standard!
    // Account Vendors may choose any other way to implement validator selection
    uint256 nonce = userOp.nonce;
    assembly {
        validator := shr(96, nonce)
    }
```

