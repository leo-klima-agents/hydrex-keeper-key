// Stand-in for part one's deploy script with every decoy the relay check must
// see through: a block comment holding an old assignment and a URL (so a `//`
// inside `/* */`), a string literal with `//` on the same line as the real
// assignment, the real assignment wrapped by a formatter and written as
// payable(address(0x...)), a commented-out assignment, a KEEPER_* identifier,
// a $KEEPER identifier, a cfg.KEEPER member, a longer hex literal after
// KEEPER =, a comparison, and a line comment right before a line that starts
// with KEEPER (the stripper must not fuse the two lines).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Deploy {
    /* KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF; see https://example.com/old */
    string constant DOCS = "https://example.com/docs"; address payable constant KEEPER =
        payable(address(0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf));
    // address constant KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF; // old
    address constant KEEPER_PREVIOUS = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    address constant $KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    bytes32 constant KEEPER_HASH = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF2B5AD5c4795c026514f8317c;

    struct Config { address KEEPER; }

    function configure(Config memory cfg) internal pure {
        cfg.KEEPER = 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    }

    function check() internal pure returns (bool) {
        return KEEPER == 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF;
    }
}
