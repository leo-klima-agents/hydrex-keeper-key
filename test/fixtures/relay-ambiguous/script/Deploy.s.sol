// Two different KEEPER assignments: the check must refuse to pick one.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Deploy {
    address constant KEEPER = 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;
}

contract DeployStaging {
    address constant KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
}
