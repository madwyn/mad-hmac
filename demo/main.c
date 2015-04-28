#include "../src/hmac_sha1.h"
#include "../src/hmac_sha2.h"
#include <string.h>

int main() {

    uint32_t hash_len = SHA256_DIGEST_SIZE;
    uint8_t  hash[hash_len];

    const uint8_t *key     = "Never tell";
    uint32_t       key_len = strlen(key);

    const uint8_t *message     = "I'm your little secret";
    uint32_t       message_len = strlen(message);

    uint32_t i = 0;

    hmac_sha256(key, key_len, message, message_len, hash, hash_len);

    for (i = 0; i < hash_len; ++i) {
        printf("%x", hash[i]);
    }

    return 0;
}
