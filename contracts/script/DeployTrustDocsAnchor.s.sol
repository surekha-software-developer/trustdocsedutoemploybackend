// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TrustDocsAnchor} from "../TrustDocsAnchor.sol";

/**
 * @title DeployTrustDocsAnchor
 * @notice Production Foundry deployment script for TrustDocsAnchor on Polygon Amoy.
 * @dev Enforces strict pre-flight environment checks, cold owner / hot anchorer role separation,
 *      unconditional initial anchorer authorization, and post-deployment state verification.
 */
contract DeployTrustDocsAnchor is Script {
    uint256 public constant POLYGON_AMOY_CHAIN_ID = 80002;

    /**
     * @notice Production entry point reading configuration from environment variables.
     */
    function run() external returns (address deployedAddress) {
        address expectedDeployer = vm.envAddress("EXPECTED_DEPLOYER_ADDRESS");
        address initialOwner = vm.envAddress("INITIAL_OWNER_ADDRESS");
        address initialAnchorer = vm.envAddress("INITIAL_ANCHORER_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        return deployWithConfig(deployerPrivateKey, expectedDeployer, initialOwner, initialAnchorer);
    }

    /**
     * @notice Deploys and configures TrustDocsAnchor with explicit configuration parameters.
     * @param deployerPrivateKey Private key of the deployer account.
     * @param expectedDeployer Expected public address corresponding to deployerPrivateKey.
     * @param initialOwner Initial owner address for Ownable2Step.
     * @param initialAnchorer Initial anchorer address to authorize on-chain.
     * @return deployedAddress Address of the deployed TrustDocsAnchor contract.
     */
    function deployWithConfig(
        uint256 deployerPrivateKey,
        address expectedDeployer,
        address initialOwner,
        address initialAnchorer
    ) public returns (address deployedAddress) {
        // 1. Strict Chain ID Guard: Live deployment script permits ONLY Polygon Amoy (80002)
        require(
            block.chainid == POLYGON_AMOY_CHAIN_ID,
            "DeployTrustDocsAnchor: Invalid chain ID. Live deployment must be strictly on Polygon Amoy (80002)"
        );

        // 2. Required nonzero addresses
        require(expectedDeployer != address(0), "DeployTrustDocsAnchor: EXPECTED_DEPLOYER_ADDRESS required");
        require(initialOwner != address(0), "DeployTrustDocsAnchor: INITIAL_OWNER_ADDRESS required");
        require(initialAnchorer != address(0), "DeployTrustDocsAnchor: INITIAL_ANCHORER_ADDRESS required");

        // 3. Private-key / expected-deployer match
        address derivedDeployer = vm.addr(deployerPrivateKey);
        require(derivedDeployer == expectedDeployer, "DeployTrustDocsAnchor: Deployer address mismatch with private key");

        // 4. Deployer equals initial owner for atomic authorization
        require(
            derivedDeployer == initialOwner,
            "DeployTrustDocsAnchor: Deployer must equal initial owner for atomic authorization"
        );

        // 5. Owner and anchorer separation
        require(initialOwner != initialAnchorer, "DeployTrustDocsAnchor: Owner and anchorer addresses must be distinct");

        console2.log("Target Chain ID   :", block.chainid);
        console2.log("Deployer Address  :", derivedDeployer);
        console2.log("Initial Owner     :", initialOwner);
        console2.log("Initial Anchorer  :", initialAnchorer);

        vm.startBroadcast(deployerPrivateKey);

        // 6. Deploy TrustDocsAnchor with initialOwner
        TrustDocsAnchor anchor = new TrustDocsAnchor(initialOwner);
        deployedAddress = address(anchor);

        // 7. Unconditional worker authorization
        anchor.setAnchorer(initialAnchorer, true);

        vm.stopBroadcast();

        // 8. Mandatory post-deployment assertions (fails if any check fails)
        require(deployedAddress.code.length > 0, "DeployTrustDocsAnchor: Contract deployment failed, no bytecode");
        require(anchor.owner() == initialOwner, "DeployTrustDocsAnchor: Owner mismatch post-deployment");
        require(anchor.isAnchorer(initialAnchorer) == true, "DeployTrustDocsAnchor: Anchorer authorization check failed");

        console2.log("TrustDocsAnchor successfully deployed at:", deployedAddress);
        return deployedAddress;
    }
}
