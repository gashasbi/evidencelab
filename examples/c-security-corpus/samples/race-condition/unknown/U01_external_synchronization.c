/* EvidenceLab synthetic corpus | CWE-362 | UNKNOWN
 * Intent: Synchronization may exist outside the snippet.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void update_shared_state(void);
void sample(void) {
    update_shared_state();
    /* UNKNOWN: caller/callee synchronization contract is absent */
}
