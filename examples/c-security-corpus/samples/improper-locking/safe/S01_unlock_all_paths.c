/* EvidenceLab synthetic corpus | CWE-667 | SAFE
 * Intent: Unlocks on both paths.
 * Educational fixture; not production code or proof of exploitability.
 */
#include <pthread.h>
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
int sample(int fail) {
    int result = 0;
    pthread_mutex_lock(&lock);
    if (fail) result = -1;
    pthread_mutex_unlock(&lock);
    return result;
}
