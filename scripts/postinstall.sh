#!/bin/bash
echo "PostInstall script:"

echo "1. React Native nodeify..."
node_modules/.bin/rn-nodeify --install 'crypto,buffer,react-native-randombytes,vm,stream,http,https,os,url,net,fs' --hack

echo "2. jetify"
npx jetify

echo "3. Patch npm packages"
npx patch-package

echo "4. Create xcconfig files..."
echo "" >ios/debug.xcconfig
echo "" >ios/release.xcconfig

echo "5. Init git submodules"
echo "This may take a while..."
git submodule update --init

if [ ! -d "ios/branch-ios-sdk" ]; then
    git clone -b 1.40.2 https://github.com/BranchMetrics/ios-branch-deep-linking-attribution ios/branch-ios-sdk
    echo "Git clone ios/branch-ios-sdk"
fi
if [ ! -d "ios/mixpanel-iphone" ]; then
    git clone -b v3.9.2 https://github.com/mixpanel/mixpanel-iphone ios/mixpanel-iphone
    echo "Git clone ios/mixpanel-iphone"
fi
