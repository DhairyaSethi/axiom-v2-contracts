#!/bin/bash

cd $(git rev-parse --show-toplevel)
source .env

forge script script/chiado/ExampleV2ClientDeploy.s.sol:ExampleV2ClientDeploy --private-key $CHIADO_PRIVATE_KEY --rpc-url $CHIADO_RPC_URL --force --verify --etherscan-api-key $ETHERSCAN_API_KEY -vvvv --broadcast
