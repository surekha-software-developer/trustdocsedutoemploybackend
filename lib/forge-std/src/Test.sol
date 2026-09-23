// SPDX-License-Identifier: MIT
pragma solidity >=0.6.2 <0.9.0;

import {Vm} from "./Vm.sol";

abstract contract Test {
    Vm public constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function assertTrue(bool condition) internal pure virtual {
        require(condition, "assertTrue failed");
    }

    function assertTrue(bool condition, string memory err) internal pure virtual {
        require(condition, err);
    }

    function assertFalse(bool condition) internal pure virtual {
        require(!condition, "assertFalse failed");
    }

    function assertFalse(bool condition, string memory err) internal pure virtual {
        require(!condition, err);
    }

    function assertEq(bytes32 a, bytes32 b) internal pure virtual {
        require(a == b, "assertEq(bytes32) failed");
    }

    function assertEq(bytes32 a, bytes32 b, string memory err) internal pure virtual {
        require(a == b, err);
    }

    function assertEq(uint256 a, uint256 b) internal pure virtual {
        require(a == b, "assertEq(uint256) failed");
    }

    function assertEq(uint256 a, uint256 b, string memory err) internal pure virtual {
        require(a == b, err);
    }

    function assertEq(address a, address b) internal pure virtual {
        require(a == b, "assertEq(address) failed");
    }

    function assertEq(address a, address b, string memory err) internal pure virtual {
        require(a == b, err);
    }

    function assertEq(string memory a, string memory b) internal pure virtual {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), "assertEq(string) failed");
    }

    function assertEq(string memory a, string memory b, string memory err) internal pure virtual {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), err);
    }

    function assertEq(bool a, bool b) internal pure virtual {
        require(a == b, "assertEq(bool) failed");
    }

    function assertEq(bool a, bool b, string memory err) internal pure virtual {
        require(a == b, err);
    }
}
