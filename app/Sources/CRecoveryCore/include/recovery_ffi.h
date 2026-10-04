/* C ABI for the LINE recovery core. Maintained by hand; must match crates/recovery-ffi/src/lib.rs. */
#ifndef RECOVERY_FFI_H
#define RECOVERY_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RecoverySession RecoverySession;

/* stage is a NUL-terminated UTF-8 string valid only during the call. total == 0 means unknown. */
typedef void (*RecoveryProgressFn)(const char *stage, uint64_t done, uint64_t total, void *user_data);

/* Static version string; do not free. */
const char *recovery_version(void);

/* Returns NULL on failure; *err_out (if non-NULL) receives an owned JSON error string. */
RecoverySession *recovery_session_new(const char *workspace_dir, char **err_out);

/* Safe with NULL. Zeroizes secrets. */
void recovery_session_free(RecoverySession *session);

/* Thread-safe cancellation request for the running operation. */
void recovery_session_cancel(RecoverySession *session);

/* Executes a JSON request; returns owned JSON {"ok":...} or {"error":{...}}. Never NULL. */
char *recovery_session_execute(RecoverySession *session,
                               const char *request_json,
                               const uint8_t *password,
                               size_t password_len,
                               RecoveryProgressFn progress,
                               void *user_data);

/* Frees any string returned by this library. Safe with NULL. */
void recovery_string_free(char *s);

#ifdef __cplusplus
}
#endif
#endif /* RECOVERY_FFI_H */
