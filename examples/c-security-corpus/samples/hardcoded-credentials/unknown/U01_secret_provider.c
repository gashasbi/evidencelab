/* EvidenceLab synthetic corpus | CWE-798 | UNKNOWN
 * Intent: Secret storage and verification depend on an external provider.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int verify_with_secret_provider(const char *user, const char *password);
int sample(const char *user, const char *password) {
    return verify_with_secret_provider(user, password);
    /* UNKNOWN: provider storage and verification policy are not shown */
}
