//SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./DeployHelpers.s.sol";
import {DeployTREXSuiteScript} from "./DeployTREXSuite.s.sol";

/**
 * @notice Main deployment script for all contracts
 * @dev Run this when you want to deploy multiple contracts at once
 *
 * Example: yarn deploy # runs this script(without`--file` flag)
 */
contract DeployScript {
    function run() external {
        // Deploy the TREX Suite
        DeployTREXSuiteScript deployTREXSuite = new DeployTREXSuiteScript();
        deployTREXSuite.run();
    }
}
