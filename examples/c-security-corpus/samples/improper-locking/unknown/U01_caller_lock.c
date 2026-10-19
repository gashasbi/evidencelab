/* EvidenceLab synthetic corpus | CWE-667 | UNKNOWN
 * Intent: Lock preconditions depend on the external function.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int update_state_under_lock(void);
int sample(void) {
    return update_state_under_lock();
    /* UNKNOWN: lock ownership requirements are not documented */
}
