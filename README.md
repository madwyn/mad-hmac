# About

mad-hmac is for HMAC-SHA1 and HMAC-SHA2 (224/256/364/512) calculation, it's small and self-contained without other dependencies.

# Features

* Small
* Easy to use
* Portable
* Free

# Usage

Three pairs of inputs:

1. `key`: the key for hashing.

2. `message`: the message to be hashed.

3. `hash`: the hash output.

As the length of the hash are fixed values, for the `hash_len`, please use the macros, e.g., `SHA1_DIGEST_SIZE`.  

```c
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
```

The above code will output: `106dc44b4868798e5c55fd253249605e8c931282dc2f593eab7651af294c6`.

# License

1. The SHA-1 implementation is from [here](https://github.com/WaterJuice/CryptLib). It's in public domain.

2. The SHA-2 and HMAC-SHA2 are from [here](https://github.com/ogay/hmac). It follows the new BSD license.

3. My work of HMAC-SHA1 follows new BSD license.