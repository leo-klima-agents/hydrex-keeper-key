// Stand-in for part one's deploy script with every decoy the relay check must
// see through: a commented-out old assignment, a block comment holding one, a
// KEEPER_* identifier, a comparison, and the real assignment wrapped over two
// lines by a formatter.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Deploy {
    // address constant KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF; // old
    /* KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF was the first one */
    address constant KEEPER_PREVIOUS = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    address constant KEEPER =
        0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf;

    function check() internal pure returns (bool) {
        return KEEPER == 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    }
}
