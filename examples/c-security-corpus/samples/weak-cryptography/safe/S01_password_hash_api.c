/* EvidenceLab synthetic corpus | CWE-327 | SAFE
 * Intent: Delegates to a dedicated password-hashing API; implementation must be reviewed.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <stddef.h>
extern int password_hash(const char *, const unsigned char *, size_t,
                         unsigned, char *, size_t);
int sample(const char *password, const unsigned char *salt, size_t salt_n,
           char *out, size_t out_n) {
    return password_hash(password, salt, salt_n, 12, out, out_n);
}
