/* VEXIL C ABI. See crates/vexil-ffi/src/lib.rs for ownership rules.
 *
 * Strings returned as `char*` are NUL-terminated and owned by the caller;
 * free with vexil_string_free (NULL means error). VexilBuf holds owned bytes;
 * free with vexil_buf_free (.data == NULL means error). Input buffers are
 * borrowed for the call only. */
#ifndef VEXIL_H
#define VEXIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct VexilBuf {
  unsigned char *data; /* NULL on error */
  size_t len;
} VexilBuf;

/* Password (symmetric) mode. */
char *vexil_encrypt_password(const unsigned char *pw, size_t pw_len,
                             const unsigned char *pt, size_t pt_len);
VexilBuf vexil_decrypt_password(const unsigned char *pw, size_t pw_len,
                                const char *ct);

/* Identity generation. Writes owned C strings to *out_identity / *out_public.
 * Returns 0 on success, -1 on error. */
int vexil_keygen(char **out_identity, char **out_public);

/* Sealed-box (public key) mode. */
char *vexil_seal_to(const char *pub_file, const unsigned char *pt, size_t pt_len);
VexilBuf vexil_open_sealed(const char *identity_file, const char *ct);

/* Signed sealed box. from_pub_file may be NULL (don't pin the sender). */
char *vexil_seal_signed(const char *pub_file, const char *sender_identity_file,
                        const unsigned char *pt, size_t pt_len);
VexilBuf vexil_open_signed(const char *identity_file, const char *ct,
                           const char *from_pub_file);

/* Multi-recipient: pubs is an array of n C strings. */
char *vexil_seal_multi(const char *const *pubs, size_t n,
                       const unsigned char *pt, size_t pt_len);
VexilBuf vexil_open_multi(const char *identity_file, const char *ct);

/* Detached signatures. vexil_verify: 1 valid, 0 invalid, -1 error. */
char *vexil_sign(const char *identity_file, const unsigned char *msg, size_t msg_len);
int vexil_verify(const char *signer_pub_file, const unsigned char *msg, size_t msg_len,
                 const char *signature);

/* Fingerprint of a public-key file. */
char *vexil_fingerprint(const char *pub_file);

/* One-shot streaming (framed) encrypt/decrypt over byte buffers. */
VexilBuf vexil_encrypt_stream(const unsigned char *pw, size_t pw_len,
                              const unsigned char *pt, size_t pt_len);
VexilBuf vexil_decrypt_stream(const unsigned char *pw, size_t pw_len,
                              const unsigned char *ct, size_t ct_len);

/* --- Live session: PQXDH handshake + Double Ratchet (forward secrecy +
 *     post-compromise security). Opaque handle; free with vexil_session_free. */
typedef struct Session VexilSession;

/* Generate a post-quantum identity; returns serialized bytes (keep secret). */
VexilBuf vexil_pq_keygen(void);

/* Build a prekey bundle for an identity. Writes the publishable bundle and the
 * private secrets. Returns 0 on success, -1 on error. */
int vexil_session_new_prekey_bundle(const unsigned char *id, size_t id_len,
                                    VexilBuf *out_bundle, VexilBuf *out_secrets);

/* Initiator: start a session from a bundle. Writes the handshake; returns an
 * owned session handle (NULL on error). */
VexilSession *vexil_session_initiate(const unsigned char *id, size_t id_len,
                                     const unsigned char *bundle, size_t bundle_len,
                                     VexilBuf *out_handshake);

/* Responder: accept a handshake with identity + bundle secrets. NULL on error. */
VexilSession *vexil_session_accept(const unsigned char *id, size_t id_len,
                                   const unsigned char *secrets, size_t secrets_len,
                                   const unsigned char *handshake, size_t handshake_len);

/* Encrypt: writes u16(header_len) || header || ciphertext to out_msg. 0/-1. */
int vexil_session_encrypt(VexilSession *s, const unsigned char *pt, size_t pt_len,
                          VexilBuf *out_msg);
/* Decrypt a u16(header_len) || header || ciphertext message. 0 ok, -1 error. */
int vexil_session_decrypt(VexilSession *s, const unsigned char *msg, size_t msg_len,
                          VexilBuf *out_pt);
/* Persist/restore full ratchet state (secrets — store encrypted). NULL on error. */
VexilBuf vexil_session_serialize(VexilSession *s);
VexilSession *vexil_session_deserialize(const unsigned char *bytes, size_t len);
void vexil_session_free(VexilSession *s);

/* --- Group messaging (sender keys). Opaque handles. --- */
typedef struct GroupSender VexilGroupSender;
typedef struct GroupReceiver VexilGroupReceiver;

VexilGroupSender *vexil_group_sender_new(void);
/* Serialize the sender's distribution; send to members over a PQ channel. */
VexilBuf vexil_group_sender_distribution(VexilGroupSender *s);
/* Encrypt + sign; writes the serialized group message to out_msg. 0/-1. */
int vexil_group_sender_encrypt(VexilGroupSender *s, const unsigned char *pt,
                               size_t pt_len, VexilBuf *out_msg);
/* Persist/restore the sender key (secret seeds — store encrypted). NULL on error. */
VexilBuf vexil_group_sender_serialize(VexilGroupSender *s);
VexilGroupSender *vexil_group_sender_deserialize(const unsigned char *bytes, size_t len);
void vexil_group_sender_free(VexilGroupSender *s);

/* Build a receiver from a serialized distribution. NULL on error. */
VexilGroupReceiver *vexil_group_receiver_new(const unsigned char *dist, size_t dist_len);
/* Verify + decrypt a serialized group message. 0 ok, -1 error. */
int vexil_group_receiver_decrypt(VexilGroupReceiver *r, const unsigned char *msg,
                                 size_t msg_len, VexilBuf *out_pt);
/* Persist/restore chain position + skipped-key cache. NULL on error. */
VexilBuf vexil_group_receiver_serialize(VexilGroupReceiver *r);
VexilGroupReceiver *vexil_group_receiver_deserialize(const unsigned char *bytes, size_t len);
void vexil_group_receiver_free(VexilGroupReceiver *r);

/* Freeing. */
void vexil_string_free(char *s);
void vexil_buf_free(VexilBuf buf);

#ifdef __cplusplus
}
#endif

#endif /* VEXIL_H */
