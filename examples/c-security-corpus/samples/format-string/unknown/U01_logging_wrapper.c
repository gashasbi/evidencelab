/* EvidenceLab synthetic corpus | CWE-134 | UNKNOWN
 * Intent: Logging wrapper behavior is unknown.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void app_log(const char *format, ...);
void sample(const char *message) {
    app_log(message);
    /* UNKNOWN: wrapper's formatting semantics are not available */
}
