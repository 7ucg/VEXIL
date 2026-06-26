# VEXIL Dart/Flutter binding

`vexil.dart` wraps the VEXIL C ABI (`crates/vexil-ffi`). It needs the native
library built per target and `package:ffi` in your Flutter app.

## 1. Add the dependency

```yaml
# pubspec.yaml
dependencies:
  ffi: ^2.1.0
```

Copy `vexil.dart` into your project (e.g. `lib/vexil.dart`).

## 2. Build the native library

The crate produces a `cdylib`. Build it per platform:

```sh
# Desktop (host): target/release/{vexil.dll | libvexil.so | libvexil.dylib}
cargo build -p vexil-ffi --release --features pq

# Android (needs cargo-ndk + NDK):
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../android/app/src/main/jniLibs \
  build -p vexil-ffi --release --features pq

# iOS (static or xcframework via cargo-lipo / cargo-xcframework):
cargo build -p vexil-ffi --release --features pq --target aarch64-apple-ios
```

Build `--features pq` so the post-quantum identities and the session/group
APIs are present.

## 3. Load it

```dart
final vx = Vexil.open();            // platform default name
// or: final vx = Vexil.openPath('/abs/path/libvexil.so');
```

On Android the loader finds `libvexil.so` in `jniLibs`. On iOS, link the
static lib and use `DynamicLibrary.process()` (adjust `Vexil.open` if so).

## 4. Use

```dart
// at-rest
final ct = vx.encryptPassword('pw', utf8.encode('secret'));
final pt = vx.decryptPassword('pw', ct);

// live PQ E2E (Double Ratchet)
final bob = vx.pqKeygen();
final (:bundle, :secrets) = vx.newPrekeyBundle(bob);
final alice = vx.pqKeygen();
final (:session, :handshake) = vx.initiate(alice, bundle);
final msg = session.encrypt(utf8.encode('hi'));
final s = vx.accept(bob, secrets, handshake);
print(utf8.decode(s.decrypt(msg)));   // hi
session.dispose(); s.dispose();

// PQ group
final sender = vx.groupSender();
final recv = vx.groupReceiver(sender.distribution());  // send distribution over the PQ channel
final gmsg = sender.encrypt(utf8.encode('team'));
print(utf8.decode(recv.decrypt(gmsg)));                // team
sender.dispose(); recv.dispose();
```

## Notes
- Treat identity bytes, bundle secrets, and group distributions as secret.
- Session and group handles own native memory — always `dispose()`.
- Analyzer errors about `malloc`/`Utf8` only appear outside a Flutter project
  (no `package:ffi` resolved); they disappear once the dependency is present.
