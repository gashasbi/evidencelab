/* EvidenceLab synthetic corpus | CWE-117 | UNKNOWN
 * Intent: Logging sink behavior is unavailable.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void app_log(const char *message);
void sample(const char *user) {
    app_log(user);
    /* UNKNOWN: output encoding behavior is not specified */
}
