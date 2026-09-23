// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DeployTrustDocsAnchor} from "../script/DeployTrustDocsAnchor.s.sol";
import {TrustDocsAnchor} from "../TrustDocsAnchor.sol";

contract DeployScriptTest is Test {
    DeployTrustDocsAnchor public script;

    uint256 internal constant TEST_DEPLOYER_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address internal constant TEST_ANCHORER = address(0x2222222222222222222222222222222222222222);

    function setUp() public {
        script = new DeployTrustDocsAnchor();
    }

    function test_DeployScript_Success() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(80002);

        address deployedAddr = script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, deployer, TEST_ANCHORER);

        assertTrue(deployedAddr != address(0), "Deployed address must be non-zero");
        assertTrue(deployedAddr.code.length > 0, "Deployed contract must contain bytecode");

        TrustDocsAnchor anchor = TrustDocsAnchor(deployedAddr);
        assertEq(anchor.owner(), deployer, "Owner must match initialOwner");
        assertTrue(anchor.isAnchorer(TEST_ANCHORER), "Initial anchorer must be authorized");
    }

    function test_DeployScript_Revert_WrongChainId() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(1);

        vm.expectRevert(
            "DeployTrustDocsAnchor: Invalid chain ID. Live deployment must be strictly on Polygon Amoy (80002)"
        );
        script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, deployer, TEST_ANCHORER);
    }

    function test_DeployScript_Revert_MissingExpectedDeployer() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: EXPECTED_DEPLOYER_ADDRESS required");
        script.deployWithConfig(TEST_DEPLOYER_KEY, address(0), deployer, TEST_ANCHORER);
    }

    function test_DeployScript_Revert_ZeroOwner() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: INITIAL_OWNER_ADDRESS required");
        script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, address(0), TEST_ANCHORER);
    }

    function test_DeployScript_Revert_ZeroAnchorer() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: INITIAL_ANCHORER_ADDRESS required");
        script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, deployer, address(0));
    }

    function test_DeployScript_Revert_DeployerMismatch() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        address wrongDeployer = address(0x9999999999999999999999999999999999999999);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: Deployer address mismatch with private key");
        script.deployWithConfig(TEST_DEPLOYER_KEY, wrongDeployer, deployer, TEST_ANCHORER);
    }

    function test_DeployScript_Revert_DeployerNotInitialOwner() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        address distinctOwner = address(0x3333333333333333333333333333333333333333);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: Deployer must equal initial owner for atomic authorization");
        script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, distinctOwner, TEST_ANCHORER);
    }

    function test_DeployScript_Revert_OwnerEqualsAnchorer() public {
        address deployer = vm.addr(TEST_DEPLOYER_KEY);
        vm.chainId(80002);

        vm.expectRevert("DeployTrustDocsAnchor: Owner and anchorer addresses must be distinct");
        script.deployWithConfig(TEST_DEPLOYER_KEY, deployer, deployer, deployer);
    }
}
