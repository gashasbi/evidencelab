/* EvidenceLab synthetic corpus | CWE-117 | SAFE
 * Intent: Uses a structured logging interface, subject to its contract.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void log_field(const char *key, const char *value);
void sample(const char *user) {
    log_field("login", user);
    /* Assumes the logging API encodes control characters safely. */
}
