## iOS release

1 - Make sure you have fastlane installed (`sudo gem install fastlane`)

2 - Bump the version number in `info.plist` and commit the change

3 - Run `METAMASK_ENVIRONMENT='production' npm run release:ios`

4 - Wait for the appstore email that the build has completed processing (10 min - 1 hour)

5 - Go to this url: https://appstoreconnect.apple.com/WebObjects/iTunesConnect.woa/ra/ng/app/1438144202/testflight?section=iosbuilds

6 - Click on the version number and then click on the "Test Details" tab

7 - Enter the release notes and save

8 - Click on the "Testers" tabs

9 - Click on the `+` sign next to Groups and select Alpha.



## Android release

1 - open android/app//build.gradle and change the versionName and bump the versionCode

2 - Save and commit

3 - Run `METAMASK_ENVIRONMENT='production' npm run release:android`

4 - Go to the playstore: https://play.google.com/apps/publish/?account=9089866037123936197

5 - Click on the App logo, then go to Release Management >> App releases

6 - Go to "Manage" inside "Closed track" (ALPHA)

7 - Click Create Release

8 - Drag the APK

9 - Add Release notes at the bottom

10 - Click Save and then click Review

11 - Start rollout to ALPHA

## Android build apk on local

- Start emulator or `yarn start:android`

- Generate keystore at `android/keystores/release.keystore`

```bash
cd android
keytool -genkey -v -keystore keystores/release.keystore -storepass android -alias androiddebugkey -keyalg RSA -keysize 2048 -keypass android -validity 10000 -dname "CN=Android Release,O=Android,C=US"
```

- Config sentry at `sentry.properties`

Ex:

```properties
defaults.url=https://sentry.io/
defaults.org=satang
defaults.project=metamask-mobile
auth.token=9d7527774a4649b78413e3d311edadaca78e171586764697be953d5e7670dceb
cli.executable=node_modules/@sentry/cli/bin/sentry-cli
```

- Add env

```bash
export METAMASK_ENVIRONMENT='local'
export BITRISEIO_ANDROID_KEYSTORE_PASSWORD=android
export BITRISEIO_ANDROID_KEYSTORE_ALIAS=androiddebugkey
export BITRISEIO_ANDROID_KEYSTORE_PRIVATE_KEY_PASSWORD=android
```

- Run command for build apk

```bash
yarn build:android:release
```

### Once you're done with both stores:
- Submit a PR with the changes
- Once it's merged create a tag on main for that version
- Go to the release pages and create a new release for that tag, including the changelog

