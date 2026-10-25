/* EvidenceLab synthetic corpus | CWE-401 | UNKNOWN
 * Intent: Ownership transfer depends on an external contract.
 * Educational fixture; not production code or proof of exploitability.
 */
extern int consume_and_release(void *resource);
int sample(void *resource) {
    return consume_and_release(resource);
    /* UNKNOWN: ownership transfer is defined externally */
}
