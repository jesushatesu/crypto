#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/crypto.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("JesusHatesU");
MODULE_DESCRIPTION("Simple example");
MODULE_VERSION("0.1");
MODULE_INFO(intree, "Y");

#define XOR_CIPHER_KEY_SIZE   16
#define XOR_CIPHER_BLOCK_SIZE 16

struct xor_cipher_ctx
{
    u8 key[XOR_CIPHER_KEY_SIZE];
};

static int xor_cipher_setkey(struct crypto_tfm *tfm, const u8 *key,
                                unsigned int len)
{
    struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
    u32 *flags = &tfm->crt_flags;

    if (len != XOR_CIPHER_KEY_SIZE)
    {
        *flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
        return -EINVAL;
    }

    memmove(ctx->key, key, XOR_CIPHER_KEY_SIZE);
    return 0;
}

static void xor_cipher_crypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
    struct xor_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
    int i;

    for (i = 0; i < XOR_CIPHER_BLOCK_SIZE; i++)
    {
        out[i] = in[i] ^ ctx->key[i];
    }
}

static struct crypto_alg xor_cipher = {
    .cra_name = "!!!!!!!!!!!xor-cipher",
    .cra_driver_name = "!!!!!!!!!!!xor-cipher-generic",
    .cra_priority = 100,
    .cra_flags = CRYPTO_ALG_TYPE_CIPHER,
    .cra_blocksize = XOR_CIPHER_BLOCK_SIZE,
    .cra_ctxsize = sizeof(struct xor_cipher_ctx),
    .cra_module = THIS_MODULE,
    .cra_u = {
        .cipher = {
            .cia_min_keysize = XOR_CIPHER_KEY_SIZE,
            .cia_max_keysize = XOR_CIPHER_KEY_SIZE,
            .cia_setkey = xor_cipher_setkey,
            .cia_encrypt = xor_cipher_crypt,
            .cia_decrypt = xor_cipher_crypt
        }
    }
};

static int __init xor_cipher_init(void)
{
    return crypto_register_alg(&xor_cipher);
}

static void __exit xor_cipher_exit(void)
{
    crypto_unregister_alg(&xor_cipher);
}


module_init(xor_cipher_init);
module_exit(xor_cipher_exit);
