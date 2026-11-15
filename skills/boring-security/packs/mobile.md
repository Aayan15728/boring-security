# Pack: Mobile (Android, iOS, cross-platform)

## When to use

The target ships an Android or iOS app — native (Kotlin/Java, Swift/ObjC) or cross-platform (React Native, Expo, Flutter, Capacitor/Cordova/Ionic, .NET MAUI, KMP). Realistic attackers: **another app on the same device**, **a web page or link the user opens**, **a malicious file/share**, **a network attacker on hostile Wi-Fi**, **someone with brief physical access to an unlocked or locked device**, or **the app's own backend user acting against other users** via the mobile API. State which one; "anyone with the APK" is a starting capability for reverse engineering, not a boundary crossing by itself.

Related packs: `browser-client` (JS inside webviews), `web-and-identity` (backend API, OAuth), `supply-chain` (SDKs, OTA updates), `data-lifecycle` (Firebase/Supabase rules).

## Discipline

```text
- Name the attacker: co-installed app, web origin/link, file/share sender, network-path attacker,
  physical-access attacker (locked vs unlocked), or a backend user. Self-impact on the same account
  is not a finding.
- The client is not a security boundary for the server. Anything enforced only in the app (hidden
  buttons, client-side role checks, "premium" flags, root/jailbreak detection, obfuscation) is
  bypassable by the device owner. Report the SERVER that trusts it, not the client that has it.
- Root/jailbreak detection, obfuscation, anti-tamper and pinning are hardening. Their absence is a
  finding only when a concrete attacker (not the device owner) gains something because of it.
- Package names, bundle IDs, URL schemes and "calling package" strings claimed by the sender are not
  identity. Real identity = signature-permission, Binder caller UID + signature check,
  App Links/Universal Links verification, iOS `sourceApplication` is unreliable — prefer
  per-request one-time state.
- Read the FINAL artefacts: merged AndroidManifest (build/intermediates/merged_manifests/...),
  final Info.plist and entitlements, network_security_config.xml, Podfile/Gradle flavors.
  Source manifests can be overridden by libraries and flavors; if the final one isn't available,
  that's a needs_validation blocker.
```

## Entry points and IPC classes

**Exported component overreach**
An Activity, Service, BroadcastReceiver or ContentProvider is reachable from other apps (`exported="true"`, or an `<intent-filter>` on pre-Android-12 targets with no explicit `exported`) and performs an app-internal action: changing settings, sending messages, launching privileged flows, returning data, or forwarding the incoming Intent. Check permission/protectionLevel (`signature` vs `normal`/`dangerous`), `android:permission` on the component, `grantUriPermissions`, `<path-permission>`, activity-alias, and what the handler does with `getIntent()` extras.

**Intent redirection and PendingIntent hijack**
The app takes an Intent (or a `Parcelable` containing one) from extras and calls `startActivity`/`startService`/`sendBroadcast`/`setResult` on it, letting another app reach the victim's **non-exported** components or `content://` grants. Or the app creates a mutable/implicit `PendingIntent` (`FLAG_MUTABLE`, empty base intent) that a receiver can fill in to act with the app's identity.

**ContentProvider and FileProvider leakage**
Provider path traversal (`openFile` building paths from URI segments), SQL injection through `selection`/`sortOrder`/projection, over-broad `<root-path>` / `<external-path path=".">` in FileProvider XML, `grantUriPermissions` combined with reflected URIs.

**Deep link and App Link abuse**
Custom schemes and unverified `https` links (`autoVerify` missing or `assetlinks.json` / `apple-app-site-association` not matching) can be claimed by other apps or triggered by any web page. Look for deep links that: complete login/OAuth/magic-link, accept a token or `redirect` param, change account state, load an arbitrary URL in a WebView, select an account/tenant, or trigger purchases/transfers — without a pending, session-bound, one-time state value.

**iOS URL scheme, Universal Link and extension trust**
`application(_:open:options:)`, `scene(_:openURLContexts:)`, `NSUserActivity` handlers performing actions on parameters; app extensions (share, action, keyboard, widget, notification service) and App Groups sharing containers/keychain groups with less-trusted extensions; `UIPasteboard` general pasteboard used for secrets.

**Task hijacking / UI spoofing (Android)**
`taskAffinity`, `allowTaskReparenting`, `launchMode="singleTask"` patterns that let a malicious app insert an Activity into the victim's task (StrandHogg-style) on the target's supported `minSdk`. Overlay/tapjacking on sensitive confirmation screens without `filterTouchesWhenObscured` / `setHideOverlayWindows`. Only report when a sensitive action is reachable and the supported OS range is affected.

## WebView and bridge classes

**JavaScript bridge reachable by untrusted origins**
`addJavascriptInterface`, `WKScriptMessageHandler`, React Native `WebView` `onMessage`/`injectedJavaScript`, Capacitor/Cordova plugins, Flutter `JavascriptChannel` — callable from any page the WebView may navigate to (including via redirects, iframes, `window.open`, error pages). The bridge must check the **current** top-frame origin at call time; an initial-URL allowlist or `startsWith` check is not enough.

**WebView settings joining origins**
`setAllowFileAccess`, `setAllowFileAccessFromFileURLs`, `setAllowUniversalAccessFromFileURLs`, `allowingReadAccessTo` broad directories, custom scheme handlers serving app files, `setMixedContentMode(ALWAYS_ALLOW)`, `WebView.setWebContentsDebuggingEnabled(true)` in release, `shouldOverrideUrlLoading` returning false for everything. A finding needs reachable attacker content **and** reachable protected content.

**Navigation to attacker URL inside a privileged WebView**
Deep link, push payload, or server field loads an arbitrary URL in a WebView that carries auth cookies/headers, a bridge, or file access.

## Data at rest and device lifecycle classes

**Sensitive storage readable by a lower-trust reader**
Tokens/PII in `SharedPreferences`/`NSUserDefaults`/plain SQLite/Realm/AsyncStorage/Hive, external storage (`/sdcard`, `getExternalFilesDir` on old APIs), world-readable modes, app-group containers shared with extensions, logs (`Log.d`, `NSLog`, `print` in release), crash reporters, screenshots/app-switcher snapshots, keyboard caches, clipboard. State **who** can read it: another app (finding), a backup extractor (finding if backups allowed and the data is a credential), only the same OS account with root (usually hardening).

**Keychain / Keystore misuse**
iOS `kSecAttrAccessibleAlways*`, missing `ThisDeviceOnly` for device-bound secrets, shared access groups; Android keys without `setUserAuthenticationRequired` where the design claims biometric protection, `setInvalidatedByBiometricEnrollment(false)` where it matters, keys used for both encryption and auth.

**Biometric / local auth that doesn't bind to crypto**
`BiometricPrompt` / `LAContext.evaluatePolicy` success used as a boolean gate with no `CryptoObject`/keychain item behind it — bypassable by anyone who can hook the process *on that device*. Real impact only if the server or a secret actually depends on it (e.g., the unlocked token is in plaintext prefs anyway).

**Backup and restore leakage**
`android:allowBackup="true"` / missing `dataExtractionRules` / `fullBackupContent` including token files; iCloud backup of files without `isExcludedFromBackup`. Restore onto another device re-activating a session that should be device-bound.

**Logout, account switch and multi-user residue**
Cached responses, WebView cookies/storage, image caches, offline DBs, push tokens, widgets, notifications that survive logout and appear for the next account.

## Network and server-trust classes

**TLS validation disabled or weakened**
Custom `TrustManager`/`HostnameVerifier` accepting all, `onReceivedSslError → proceed()`, `NSAllowsArbitraryLoads`, `cleartextTrafficPermitted="true"`, debug `network_security_config` leaking into release, `<debug-overrides>` misuse, Flutter `badCertificateCallback => true`, RN/OkHttp/Alamofire custom sessions. Network-path attacker → read/modify API traffic.

**Pinning: present but wrong**
Pin to a leaf that rotates (availability, not security), pins checked only on some clients (OkHttp yes, WebView no), pin bypass on error fallback. Missing pinning alone is hardening unless the threat model explicitly requires it.

**Client-trusted server decisions (mobile API)**
The backend trusts values only the app is supposed to send: `isPremium`, `role`, price, receipt status without server-side receipt verification, device-integrity attestations not verified server-side (Play Integrity / App Attest tokens decoded but not checked), user IDs in the body. Hand the server side to `core-classes.md#Access control` if needed.

**Secrets in the binary**
API keys, signing secrets, backend admin tokens, third-party secret keys (Stripe `sk_`, AWS keys, Firebase admin service accounts) in code, `BuildConfig`, `strings.xml`, `.plist`, JS bundles, `.env` baked by Expo/RN. Public client IDs and restricted publishable keys are not findings; *what can the key do* decides it.

## Cross-platform specifics

- **React Native / Expo**: JS bundle is public; `react-native-config` / `expo-constants` `extra` values are not secret; `Linking` handlers; `react-native-webview` with `originWhitelist={['*']}` + `onMessage` doing privileged things; CodePush/EAS Update signing and channel trust (→ `packs/supply-chain.md`).
- **Flutter**: platform channels (`MethodChannel`) reachable from native exported components; `flutter_secure_storage` options; Dart `HttpClient` cert callbacks.
- **Capacitor/Cordova/Ionic**: plugin allowlists, `server.allowNavigation`, `<access origin="*">`, `cordova-plugin-inappbrowser` with bridge access.
- **.NET MAUI / Xamarin**: `HybridWebView`/`EvaluateJavaScriptAsync` bridges, `ServerCertificateCustomValidationCallback`.

## Moves

- Enumerate: every component in the merged manifest + export status + permission; every URL scheme, associated domain, intent filter, document type; every WebView instance with its settings and bridge objects; every storage location with its protection class; every network client with its TLS config; every embedded key with what it authorizes.
- Grep starters: `exported="true"`, `<intent-filter`, `getIntent()`, `getParcelableExtra`, `startActivity(`, `PendingIntent.get`, `FLAG_MUTABLE`, `addJavascriptInterface`, `setAllowFileAccess`, `setJavaScriptEnabled(true)`, `onReceivedSslError`, `X509TrustManager`, `allowBackup`, `cleartextTrafficPermitted`, `NSAllowsArbitraryLoads`, `kSecAttrAccessibleAlways`, `UIPasteboard.general`, `evaluatePolicy`, `WKScriptMessageHandler`, `openURL`, `AsyncStorage`, `MethodChannel`, `originWhitelist`.
- Local proofs on an emulator/simulator with a mocked backend: `adb shell am start -n <pkg>/<activity> --es key value`, `adb shell content query --uri content://...`, `xcrun simctl openurl booted "<scheme>://..."`.

## Gate

1. Name the attacker's starting position (co-installed app, link/web origin, file sender, network path, physical locked/unlocked, backend user), the entry channel, what they control, the control that should stop them, and the unauthorized action or data.
2. Cite the final manifest/plist/entitlement/network-config line. If only the source manifest is available and merging could change the answer → needs_validation ("final merged manifest not available").
3. WebView findings cite both the navigation/origin control and the privileged sink. IPC findings cite the caller-identity check (or its absence) and the per-resource authorization. Storage findings name the lower-trust reader.
