// VEXIL Dart/Flutter binding over the C ABI (vexil-ffi).
//
// Load the native library built from crates/vexil-ffi:
//   - Android: libvexil.so   - iOS/macOS: vexil.framework / libvexil.dylib
//   - Windows: vexil.dll     - Linux: libvexil.so
//
// Usage:
//   final vx = Vexil.open();
//   final ct = vx.encryptPassword('pw', utf8.encode('secret'));
//   final pt = vx.decryptPassword('pw', ct); // throws on failure
//
// All native allocations are freed inside these wrappers; callers only deal
// with Dart String / Uint8List.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// --- C struct ---
final class _VexilBuf extends Struct {
  external Pointer<Uint8> data;
  @Size()
  external int len;
}

// --- native signatures ---
typedef _EncPwC =
    Pointer<Utf8> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _EncPwD =
    Pointer<Utf8> Function(Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _DecPwC = _VexilBuf Function(Pointer<Uint8>, Size, Pointer<Utf8>);
typedef _DecPwD = _VexilBuf Function(Pointer<Uint8>, int, Pointer<Utf8>);
typedef _KeygenC =
    Int32 Function(Pointer<Pointer<Utf8>>, Pointer<Pointer<Utf8>>);
typedef _KeygenD = int Function(Pointer<Pointer<Utf8>>, Pointer<Pointer<Utf8>>);
typedef _SealC = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Uint8>, Size);
typedef _SealD = Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Uint8>, int);
typedef _OpenC = _VexilBuf Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _OpenD = _VexilBuf Function(Pointer<Utf8>, Pointer<Utf8>);
typedef _StrFreeC = Void Function(Pointer<Utf8>);
typedef _StrFreeD = void Function(Pointer<Utf8>);
typedef _BufFreeC = Void Function(_VexilBuf);
typedef _BufFreeD = void Function(_VexilBuf);

// signed / multi / sign-verify / fingerprint / streaming
typedef _SignedC =
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, Size);
typedef _SignedD =
    Pointer<Utf8> Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Uint8>, int);
typedef _OpenSignedC =
    _VexilBuf Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _OpenSignedD =
    _VexilBuf Function(Pointer<Utf8>, Pointer<Utf8>, Pointer<Utf8>);
typedef _MultiC =
    Pointer<Utf8> Function(Pointer<Pointer<Utf8>>, Size, Pointer<Uint8>, Size);
typedef _MultiD =
    Pointer<Utf8> Function(Pointer<Pointer<Utf8>>, int, Pointer<Uint8>, int);
typedef _VerifyC =
    Int32 Function(Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Utf8>);
typedef _VerifyD =
    int Function(Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>);
typedef _FprC = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _FprD = Pointer<Utf8> Function(Pointer<Utf8>);
typedef _StreamC =
    _VexilBuf Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _StreamD = _VexilBuf Function(Pointer<Uint8>, int, Pointer<Uint8>, int);

// session
typedef _PqKgC = _VexilBuf Function();
typedef _PqKgD = _VexilBuf Function();
typedef _BundleC =
    Int32 Function(
      Pointer<Uint8>,
      Size,
      Pointer<_VexilBuf>,
      Pointer<_VexilBuf>,
    );
typedef _BundleD =
    int Function(Pointer<Uint8>, int, Pointer<_VexilBuf>, Pointer<_VexilBuf>);
typedef _InitC =
    Pointer<Void> Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<_VexilBuf>,
    );
typedef _InitD =
    Pointer<Void> Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<_VexilBuf>,
    );
typedef _AcceptC =
    Pointer<Void> Function(
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
      Pointer<Uint8>,
      Size,
    );
typedef _AcceptD =
    Pointer<Void> Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
    );
typedef _SEncC =
    Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<_VexilBuf>);
typedef _SEncD =
    int Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<_VexilBuf>);
typedef _SDecC =
    Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<_VexilBuf>);
typedef _SDecD =
    int Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<_VexilBuf>);
typedef _SFreeC = Void Function(Pointer<Void>);
typedef _SFreeD = void Function(Pointer<Void>);

// groups
typedef _GSNewC = Pointer<Void> Function();
typedef _GSNewD = Pointer<Void> Function();
typedef _GSDistC = _VexilBuf Function(Pointer<Void>);
typedef _GSDistD = _VexilBuf Function(Pointer<Void>);
typedef _GSEncC =
    Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<_VexilBuf>);
typedef _GSEncD =
    int Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<_VexilBuf>);
typedef _GRNewC = Pointer<Void> Function(Pointer<Uint8>, Size);
typedef _GRNewD = Pointer<Void> Function(Pointer<Uint8>, int);
typedef _GRDecC =
    Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<_VexilBuf>);
typedef _GRDecD =
    int Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<_VexilBuf>);
typedef _GFreeC = Void Function(Pointer<Void>);
typedef _GFreeD = void Function(Pointer<Void>);

class VexilException implements Exception {
  final String message;
  VexilException(this.message);
  @override
  String toString() => 'VexilException: $message';
}

class Keypair {
  final String identity; // VEXIL-IDENTITY-v1 text (keep secret)
  final String public; // VEXIL-KEY-v1 text (shareable)
  Keypair(this.identity, this.public);
}

class Vexil {
  final _EncPwD _encPw;
  final _DecPwD _decPw;
  final _KeygenD _keygen;
  final _SealD _seal;
  final _OpenD _open;
  final _StrFreeD _strFree;
  final _BufFreeD _bufFree;
  final _PqKgD _pqKeygen;
  final _BundleD _bundle;
  final _InitD _initiate;
  final _AcceptD _accept;
  final _SEncD sEnc;
  final _SDecD sDec;
  final _SFreeD sFree;
  final _GSNewD _gsNew;
  final _GSDistD gsDist;
  final _GSEncD gsEnc;
  final _GFreeD gsFree;
  final _GRNewD _grNew;
  final _GRDecD grDec;
  final _GFreeD grFree;
  final _SignedD _sealSigned;
  final _OpenSignedD _openSigned;
  final _MultiD _sealMulti;
  final _OpenD _openMulti;
  final _SealD _sign;
  final _VerifyD _verify;
  final _FprD _fpr;
  final _StreamD _encStream;
  final _StreamD _decStream;
  final _GSDistD sSer; // vexil_session_serialize
  final _GRNewD sDeser; // vexil_session_deserialize
  final _GSDistD gsSer;
  final _GRNewD gsDeser;
  final _GSDistD grSer;
  final _GRNewD grDeser;

  Vexil._(DynamicLibrary lib)
    : _encPw = lib.lookupFunction<_EncPwC, _EncPwD>('vexil_encrypt_password'),
      _decPw = lib.lookupFunction<_DecPwC, _DecPwD>('vexil_decrypt_password'),
      _keygen = lib.lookupFunction<_KeygenC, _KeygenD>('vexil_keygen'),
      _seal = lib.lookupFunction<_SealC, _SealD>('vexil_seal_to'),
      _open = lib.lookupFunction<_OpenC, _OpenD>('vexil_open_sealed'),
      _strFree = lib.lookupFunction<_StrFreeC, _StrFreeD>('vexil_string_free'),
      _bufFree = lib.lookupFunction<_BufFreeC, _BufFreeD>('vexil_buf_free'),
      _pqKeygen = lib.lookupFunction<_PqKgC, _PqKgD>('vexil_pq_keygen'),
      _bundle = lib.lookupFunction<_BundleC, _BundleD>(
        'vexil_session_new_prekey_bundle',
      ),
      _initiate = lib.lookupFunction<_InitC, _InitD>('vexil_session_initiate'),
      _accept = lib.lookupFunction<_AcceptC, _AcceptD>('vexil_session_accept'),
      sEnc = lib.lookupFunction<_SEncC, _SEncD>('vexil_session_encrypt'),
      sDec = lib.lookupFunction<_SDecC, _SDecD>('vexil_session_decrypt'),
      sFree = lib.lookupFunction<_SFreeC, _SFreeD>('vexil_session_free'),
      _gsNew = lib.lookupFunction<_GSNewC, _GSNewD>('vexil_group_sender_new'),
      gsDist = lib.lookupFunction<_GSDistC, _GSDistD>(
        'vexil_group_sender_distribution',
      ),
      gsEnc = lib.lookupFunction<_GSEncC, _GSEncD>(
        'vexil_group_sender_encrypt',
      ),
      gsFree = lib.lookupFunction<_GFreeC, _GFreeD>('vexil_group_sender_free'),
      _grNew = lib.lookupFunction<_GRNewC, _GRNewD>('vexil_group_receiver_new'),
      grDec = lib.lookupFunction<_GRDecC, _GRDecD>(
        'vexil_group_receiver_decrypt',
      ),
      grFree = lib.lookupFunction<_GFreeC, _GFreeD>(
        'vexil_group_receiver_free',
      ),
      _sealSigned = lib.lookupFunction<_SignedC, _SignedD>('vexil_seal_signed'),
      _openSigned = lib.lookupFunction<_OpenSignedC, _OpenSignedD>(
        'vexil_open_signed',
      ),
      _sealMulti = lib.lookupFunction<_MultiC, _MultiD>('vexil_seal_multi'),
      _openMulti = lib.lookupFunction<_OpenC, _OpenD>('vexil_open_multi'),
      _sign = lib.lookupFunction<_SealC, _SealD>('vexil_sign'),
      _verify = lib.lookupFunction<_VerifyC, _VerifyD>('vexil_verify'),
      _fpr = lib.lookupFunction<_FprC, _FprD>('vexil_fingerprint'),
      _encStream = lib.lookupFunction<_StreamC, _StreamD>(
        'vexil_encrypt_stream',
      ),
      _decStream = lib.lookupFunction<_StreamC, _StreamD>(
        'vexil_decrypt_stream',
      ),
      sSer = lib.lookupFunction<_GSDistC, _GSDistD>('vexil_session_serialize'),
      sDeser = lib.lookupFunction<_GRNewC, _GRNewD>(
        'vexil_session_deserialize',
      ),
      gsSer = lib.lookupFunction<_GSDistC, _GSDistD>(
        'vexil_group_sender_serialize',
      ),
      gsDeser = lib.lookupFunction<_GRNewC, _GRNewD>(
        'vexil_group_sender_deserialize',
      ),
      grSer = lib.lookupFunction<_GSDistC, _GSDistD>(
        'vexil_group_receiver_serialize',
      ),
      grDeser = lib.lookupFunction<_GRNewC, _GRNewD>(
        'vexil_group_receiver_deserialize',
      );

  /// Open the platform native library by its conventional name.
  factory Vexil.open() {
    final lib = Platform.isWindows
        ? DynamicLibrary.open('vexil.dll')
        : Platform.isMacOS
        ? DynamicLibrary.open('libvexil.dylib')
        : DynamicLibrary.open('libvexil.so');
    return Vexil._(lib);
  }

  /// Open from an explicit path.
  factory Vexil.openPath(String path) => Vexil._(DynamicLibrary.open(path));

  String encryptPassword(String password, Uint8List plaintext) {
    final pw = password.toNativeUtf8();
    final pt = _toNative(plaintext);
    try {
      final res = _encPw(
        pw.cast(),
        utf8.encode(password).length,
        pt,
        plaintext.length,
      );
      if (res == nullptr) throw VexilException('encrypt failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      malloc.free(pw);
      malloc.free(pt);
    }
  }

  Uint8List decryptPassword(String password, String ciphertext) {
    final pwBytes = utf8.encode(password);
    final pw = _toNative(Uint8List.fromList(pwBytes));
    final ct = ciphertext.toNativeUtf8();
    try {
      final buf = _decPw(pw, pwBytes.length, ct.cast());
      return _takeBuf(buf, 'decrypt failed');
    } finally {
      malloc.free(pw);
      malloc.free(ct);
    }
  }

  Keypair keygen() {
    final outId = malloc<Pointer<Utf8>>();
    final outPub = malloc<Pointer<Utf8>>();
    try {
      if (_keygen(outId, outPub) != 0) throw VexilException('keygen failed');
      final id = outId.value.toDartString();
      final pub = outPub.value.toDartString();
      _strFree(outId.value);
      _strFree(outPub.value);
      return Keypair(id, pub);
    } finally {
      malloc.free(outId);
      malloc.free(outPub);
    }
  }

  String sealTo(String publicKeyFile, Uint8List plaintext) {
    final pk = publicKeyFile.toNativeUtf8();
    final pt = _toNative(plaintext);
    try {
      final res = _seal(pk, pt, plaintext.length);
      if (res == nullptr) throw VexilException('seal failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      malloc.free(pk);
      malloc.free(pt);
    }
  }

  Uint8List openSealed(String identityFile, String ciphertext) {
    final id = identityFile.toNativeUtf8();
    final ct = ciphertext.toNativeUtf8();
    try {
      final buf = _open(id.cast(), ct.cast());
      return _takeBuf(buf, 'open failed');
    } finally {
      malloc.free(id);
      malloc.free(ct);
    }
  }

  /// Signed sealed box: seal to [publicKeyFile], signed by [senderIdentityFile].
  String sealSigned(
    String publicKeyFile,
    String senderIdentityFile,
    Uint8List plaintext,
  ) {
    final pk = publicKeyFile.toNativeUtf8();
    final sid = senderIdentityFile.toNativeUtf8();
    final pt = _toNative(plaintext);
    try {
      final res = _sealSigned(pk, sid, pt, plaintext.length);
      if (res == nullptr) throw VexilException('seal signed failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      malloc.free(pk);
      malloc.free(sid);
      malloc.free(pt);
    }
  }

  /// Open a signed sealed box. Pass [fromPublicFile] to pin the sender.
  Uint8List openSigned(
    String identityFile,
    String ciphertext, {
    String? fromPublicFile,
  }) {
    final id = identityFile.toNativeUtf8();
    final ct = ciphertext.toNativeUtf8();
    final from = fromPublicFile?.toNativeUtf8() ?? nullptr;
    try {
      final buf = _openSigned(id, ct, from.cast());
      return _takeBuf(buf, 'open signed failed');
    } finally {
      malloc.free(id);
      malloc.free(ct);
      if (from != nullptr) malloc.free(from);
    }
  }

  /// Multi-recipient: seal once to several recipient public-key files.
  String sealMulti(List<String> publicKeyFiles, Uint8List plaintext) {
    final n = publicKeyFiles.length;
    final arr = malloc<Pointer<Utf8>>(n);
    final ptrs = <Pointer<Utf8>>[];
    for (var i = 0; i < n; i++) {
      ptrs.add(publicKeyFiles[i].toNativeUtf8());
      arr[i] = ptrs[i];
    }
    final pt = _toNative(plaintext);
    try {
      final res = _sealMulti(arr, n, pt, plaintext.length);
      if (res == nullptr) throw VexilException('seal multi failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      for (final p in ptrs) {
        malloc.free(p);
      }
      malloc.free(arr);
      malloc.free(pt);
    }
  }

  /// Open a multi-recipient envelope with your identity.
  Uint8List openMulti(String identityFile, String ciphertext) {
    final id = identityFile.toNativeUtf8();
    final ct = ciphertext.toNativeUtf8();
    try {
      return _takeBuf(_openMulti(id.cast(), ct.cast()), 'open multi failed');
    } finally {
      malloc.free(id);
      malloc.free(ct);
    }
  }

  /// Detached signature over [msg] with an identity file. Returns `VEXSIG-...`.
  String sign(String identityFile, Uint8List msg) {
    final id = identityFile.toNativeUtf8();
    final m = _toNative(msg);
    try {
      final res = _sign(id, m, msg.length);
      if (res == nullptr) throw VexilException('sign failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      malloc.free(id);
      malloc.free(m);
    }
  }

  /// Verify a `VEXSIG-...` detached signature. Returns true if valid.
  bool verify(String signerPublicFile, Uint8List msg, String signature) {
    final pk = signerPublicFile.toNativeUtf8();
    final m = _toNative(msg);
    final sig = signature.toNativeUtf8();
    try {
      final r = _verify(pk, m, msg.length, sig);
      if (r < 0) throw VexilException('verify error');
      return r == 1;
    } finally {
      malloc.free(pk);
      malloc.free(m);
      malloc.free(sig);
    }
  }

  /// Fingerprint of a public-key file (`a1b2-c3d4-e5f6-7890`).
  String fingerprint(String publicKeyFile) {
    final pk = publicKeyFile.toNativeUtf8();
    try {
      final res = _fpr(pk);
      if (res == nullptr) throw VexilException('fingerprint failed');
      final s = res.toDartString();
      _strFree(res);
      return s;
    } finally {
      malloc.free(pk);
    }
  }

  /// One-shot streaming encrypt under a password (framed stream bytes).
  Uint8List encryptStream(String password, Uint8List plaintext) {
    final pwBytes = utf8.encode(password);
    final pw = _toNative(Uint8List.fromList(pwBytes));
    final pt = _toNative(plaintext);
    try {
      return _takeBuf(
        _encStream(pw, pwBytes.length, pt, plaintext.length),
        'stream encrypt failed',
      );
    } finally {
      malloc.free(pw);
      malloc.free(pt);
    }
  }

  /// One-shot streaming decrypt of a framed stream.
  Uint8List decryptStream(String password, Uint8List ciphertext) {
    final pwBytes = utf8.encode(password);
    final pw = _toNative(Uint8List.fromList(pwBytes));
    final ct = _toNative(ciphertext);
    try {
      return _takeBuf(
        _decStream(pw, pwBytes.length, ct, ciphertext.length),
        'stream decrypt failed',
      );
    } finally {
      malloc.free(pw);
      malloc.free(ct);
    }
  }

  Pointer<Uint8> _toNative(Uint8List data) {
    final p = malloc<Uint8>(data.length == 0 ? 1 : data.length);
    p.asTypedList(data.length).setAll(0, data);
    return p;
  }

  Uint8List _takeBuf(_VexilBuf buf, String errMsg) {
    if (buf.data == nullptr) throw VexilException(errMsg);
    final out = Uint8List.fromList(buf.data.asTypedList(buf.len));
    _bufFree(buf);
    return out;
  }

  // Read + free a VexilBuf written through an out-pointer.
  Uint8List takeOut(Pointer<_VexilBuf> out, String err) {
    final b = out.ref;
    if (b.data == nullptr) throw VexilException(err);
    final v = Uint8List.fromList(b.data.asTypedList(b.len));
    _bufFree(b);
    return v;
  }

  Pointer<Uint8> nat(Uint8List d) => _toNative(d);
  void freeNat(Pointer<Uint8> p) => malloc.free(p);
  Uint8List takeByValue(_VexilBuf b, String err) => _takeBuf(b, err);

  // --- Live session (Double Ratchet) ---

  /// Generate a post-quantum identity (serialized bytes; keep secret).
  Uint8List pqKeygen() => _takeBuf(_pqKeygen(), 'pq keygen failed');

  /// Build a prekey bundle for an identity: returns the publishable `bundle`
  /// and the private `secrets` (keep them).
  ({Uint8List bundle, Uint8List secrets}) newPrekeyBundle(Uint8List identity) {
    final id = _toNative(identity);
    final ob = malloc<_VexilBuf>();
    final os = malloc<_VexilBuf>();
    try {
      if (_bundle(id, identity.length, ob, os) != 0) {
        throw VexilException('prekey bundle failed');
      }
      return (bundle: takeOut(ob, 'bundle'), secrets: takeOut(os, 'secrets'));
    } finally {
      malloc.free(id);
      malloc.free(ob);
      malloc.free(os);
    }
  }

  /// Initiator: start a session toward a recipient's bundle. Returns the live
  /// session and the `handshake` bytes to send with the first message.
  ({VexilSession session, Uint8List handshake}) initiate(
    Uint8List identity,
    Uint8List bundle,
  ) {
    final id = _toNative(identity);
    final bu = _toNative(bundle);
    final oh = malloc<_VexilBuf>();
    try {
      final ptr = _initiate(id, identity.length, bu, bundle.length, oh);
      if (ptr == nullptr) throw VexilException('initiate failed');
      return (
        session: VexilSession._(this, ptr),
        handshake: takeOut(oh, 'handshake'),
      );
    } finally {
      malloc.free(id);
      malloc.free(bu);
      malloc.free(oh);
    }
  }

  /// Responder: accept a handshake with your identity + bundle secrets.
  VexilSession accept(
    Uint8List identity,
    Uint8List secrets,
    Uint8List handshake,
  ) {
    final id = _toNative(identity);
    final se = _toNative(secrets);
    final hs = _toNative(handshake);
    try {
      final ptr = _accept(
        id,
        identity.length,
        se,
        secrets.length,
        hs,
        handshake.length,
      );
      if (ptr == nullptr) throw VexilException('accept failed');
      return VexilSession._(this, ptr);
    } finally {
      malloc.free(id);
      malloc.free(se);
      malloc.free(hs);
    }
  }

  /// Restore a session from [VexilSession.serialize] bytes (e.g. after restart).
  VexilSession sessionFromBytes(Uint8List state) {
    final s = _toNative(state);
    try {
      final ptr = sDeser(s, state.length);
      if (ptr == nullptr) throw VexilException('bad session state');
      return VexilSession._(this, ptr);
    } finally {
      malloc.free(s);
    }
  }

  // --- Groups (sender keys) ---

  /// Create a group sender key (you broadcast its [VexilGroupSender.distribution]).
  VexilGroupSender groupSender() => VexilGroupSender._(this, _gsNew());

  /// Build a group receiver from a sender's distribution bytes.
  VexilGroupReceiver groupReceiver(Uint8List distribution) {
    final d = _toNative(distribution);
    try {
      final ptr = _grNew(d, distribution.length);
      if (ptr == nullptr) throw VexilException('bad group distribution');
      return VexilGroupReceiver._(this, ptr);
    } finally {
      malloc.free(d);
    }
  }

  /// Restore a group sender from [VexilGroupSender.serialize] bytes.
  VexilGroupSender groupSenderFromBytes(Uint8List state) {
    final s = _toNative(state);
    try {
      final ptr = gsDeser(s, state.length);
      if (ptr == nullptr) throw VexilException('bad group sender state');
      return VexilGroupSender._(this, ptr);
    } finally {
      malloc.free(s);
    }
  }

  /// Restore a group receiver from [VexilGroupReceiver.serialize] bytes.
  VexilGroupReceiver groupReceiverFromBytes(Uint8List state) {
    final s = _toNative(state);
    try {
      final ptr = grDeser(s, state.length);
      if (ptr == nullptr) throw VexilException('bad group receiver state');
      return VexilGroupReceiver._(this, ptr);
    } finally {
      malloc.free(s);
    }
  }
}

/// A group sender key. Broadcast [distribution] to members, then [encrypt].
class VexilGroupSender {
  final Vexil _vx;
  Pointer<Void> _ptr;
  VexilGroupSender._(this._vx, this._ptr);

  /// Serialized sender-key distribution (send over a pairwise PQ channel).
  Uint8List distribution() => _vx.takeByValue(_vx.gsDist(_ptr), 'distribution');

  /// Serialize the full sender key (secret seeds — store encrypted at rest).
  /// Restore with [Vexil.groupSenderFromBytes].
  Uint8List serialize() =>
      _vx.takeByValue(_vx.gsSer(_ptr), 'group sender serialize');

  /// Encrypt + sign the next group message (serialized).
  Uint8List encrypt(Uint8List plaintext) {
    final pt = _vx.nat(plaintext);
    final out = malloc<_VexilBuf>();
    try {
      if (_vx.gsEnc(_ptr, pt, plaintext.length, out) != 0) {
        throw VexilException('group encrypt failed');
      }
      return _vx.takeOut(out, 'group encrypt');
    } finally {
      _vx.freeNat(pt);
      malloc.free(out);
    }
  }

  /// Free the native sender.
  void dispose() {
    if (_ptr != nullptr) {
      _vx.gsFree(_ptr);
      _ptr = nullptr;
    }
  }
}

/// A receiver's view of one group sender.
class VexilGroupReceiver {
  final Vexil _vx;
  Pointer<Void> _ptr;
  VexilGroupReceiver._(this._vx, this._ptr);

  /// Verify + decrypt a serialized group message.
  Uint8List decrypt(Uint8List message) {
    final m = _vx.nat(message);
    final out = malloc<_VexilBuf>();
    try {
      if (_vx.grDec(_ptr, m, message.length, out) != 0) {
        throw VexilException('group decrypt failed');
      }
      return _vx.takeOut(out, 'group decrypt');
    } finally {
      _vx.freeNat(m);
      malloc.free(out);
    }
  }

  /// Serialize chain position + skipped-key cache (contains secrets).
  /// Restore with [Vexil.groupReceiverFromBytes].
  Uint8List serialize() =>
      _vx.takeByValue(_vx.grSer(_ptr), 'group receiver serialize');

  /// Free the native receiver.
  void dispose() {
    if (_ptr != nullptr) {
      _vx.grFree(_ptr);
      _ptr = nullptr;
    }
  }
}

/// A live Double Ratchet session handle. Call [dispose] when done.
class VexilSession {
  final Vexil _vx;
  Pointer<Void> _ptr;
  VexilSession._(this._vx, this._ptr);

  /// Encrypt the next message; returns `header(40) || ciphertext`.
  Uint8List encrypt(Uint8List plaintext) {
    final pt = _vx.nat(plaintext);
    final out = malloc<_VexilBuf>();
    try {
      if (_vx.sEnc(_ptr, pt, plaintext.length, out) != 0) {
        throw VexilException('session encrypt failed');
      }
      return _vx.takeOut(out, 'encrypt');
    } finally {
      _vx.freeNat(pt);
      malloc.free(out);
    }
  }

  /// Decrypt a `header(40) || ciphertext` message.
  Uint8List decrypt(Uint8List message) {
    final m = _vx.nat(message);
    final out = malloc<_VexilBuf>();
    try {
      if (_vx.sDec(_ptr, m, message.length, out) != 0) {
        throw VexilException('session decrypt failed');
      }
      return _vx.takeOut(out, 'decrypt');
    } finally {
      _vx.freeNat(m);
      malloc.free(out);
    }
  }

  /// Serialize the full ratchet state so the conversation survives a restart.
  /// Contains secrets — store encrypted. Restore with [Vexil.sessionFromBytes].
  Uint8List serialize() => _vx.takeByValue(_vx.sSer(_ptr), 'session serialize');

  /// Free the native session. Safe to call once.
  void dispose() {
    if (_ptr != nullptr) {
      _vx.sFree(_ptr);
      _ptr = nullptr;
    }
  }
}
