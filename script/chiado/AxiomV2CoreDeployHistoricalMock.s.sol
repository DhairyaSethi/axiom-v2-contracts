// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Script.sol";

import {CHIADO_CHAIN_ID} from "../../contracts/libraries/configuration/AxiomV2Configuration.sol";
import {AxiomDeployBase} from "../base/AxiomDeployBase.sol";

contract AxiomV2CoreDeployHistoricalMock is AxiomDeployBase {
    function run() external {
        vm.startBroadcast();

        (
            address timelock,
            address guardian,
            address unfreeze,
            address coreProver,

        ) = _getMultisigAddresses(CHIADO_CHAIN_ID);
        address verifier = _deployCoreVerifier(CHIADO_CHAIN_ID);

        _deployCoreHistoricalMock(
            verifier,
            timelock,
            guardian,
            unfreeze,
            coreProver
        );
        vm.stopBroadcast();
    }
}
