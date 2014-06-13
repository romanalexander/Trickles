#ifdef OPENSSL_HMAC
#ifdef USE_SHA1
#include "../../net/ipv4/crypto/sha.h"
#else
#include "../../net/ipv4/crypto/md5.h"
#endif

#else
#include "../../net/ipv4/crypto/hmac.h"
#endif

#include "../../net/ipv4/crypto/aes.h"
