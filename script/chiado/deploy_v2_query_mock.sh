#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/chiado/AxiomV2QueryDeployMock.s.sol:AxiomV2QueryDeployMock --private-key $CHIADO_PRIVATE_KEY --rpc-url $CHIADO_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv --broadcast 

# if chiado slow and fails to verify, https://github.com/foundry-rs/foundry/issues/2435 
#forge script script/chiado/AxiomV2QueryDeployMock.s.sol:AxiomV2QueryDeployMock --sender $SENDER_ADDRESS --keystore $KEYSTORE_PATH --rpc-url $CHIADO_RPC_URL --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv
