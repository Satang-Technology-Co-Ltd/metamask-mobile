#!/bin/bash
echo "node_modules/ethereumjs-wallet/dist/index.js:401"
cp custom-lib/ethereumjs-wallet.js node_modules/ethereumjs-wallet/dist/index.js

echo "node_modules/@metamask/controllers/dist/keyring/KeyringController.js:238"
cp custom-lib/KeyringController.js node_modules/@metamask/controllers/dist/keyring/KeyringController.js

echo "node_modules/@metamask/controllers/dist/transaction/TransactionController.js:318"
cp custom-lib/TransactionController.js node_modules/@metamask/controllers/dist/transaction/TransactionController.js
