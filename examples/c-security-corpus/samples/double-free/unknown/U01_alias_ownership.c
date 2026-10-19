/* EvidenceLab synthetic corpus | CWE-415 | UNKNOWN
 * Intent: Ownership and pointer aliasing are unknown.
 * Educational fixture; not production code or proof of exploitability.
 */
extern void release_object(void *object);
void sample(void *first, void *second) {
    release_object(first);
    release_object(second);
    /* UNKNOWN: whether both pointers alias is not established */
}
