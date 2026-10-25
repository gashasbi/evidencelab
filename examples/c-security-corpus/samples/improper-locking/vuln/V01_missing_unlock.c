/* EvidenceLab synthetic corpus | CWE-667 | VULN
 * Intent: An error path returns while holding a mutex.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int sample(int fail) {
    pthread_mutex_lock(&lock);
    if (fail) return -1; /* VULN: returns while holding the lock */
    pthread_mutex_unlock(&lock);
    return 0;
}
