#include "vault-bridge.h"

#include <gcrypt.h>
#include <string.h>

#define VAULT_KEY 32
#define VAULT_TAG 16

static gboolean
vault_bridge_ready (void)
{
    static gsize done = 0;
    static gboolean ok = FALSE;

    if (g_once_init_enter (&done)) {
        if (gcry_check_version ("1.6.0") != NULL) {
            gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
            gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
            ok = TRUE;
        }
        g_once_init_leave (&done, 1);
    }
    return ok;
}

gboolean
vault_bridge_scrypt (const guint8 *password, gsize password_length,
                     const guint8 *salt, gsize salt_length,
                     guint64 n, gint r, gint p,
                     guint8 *key, gsize key_length)
{
    static const guint8 empty = 0;

    if (!vault_bridge_ready () || r != 8 || p < 1 || n < 2 || (n & (n - 1)) != 0 || n > G_MAXULONG)
        return FALSE;
    return gcry_kdf_derive (password_length > 0 ? password : &empty, password_length,
                            GCRY_KDF_SCRYPT, (int) n,
                            salt, salt_length, (unsigned long) p,
                            key_length, key) == 0;
}

static gcry_cipher_hd_t
vault_bridge_cipher (const guint8 *key, gsize key_length, const guint8 *nonce, gsize nonce_length)
{
    gcry_cipher_hd_t handle = NULL;

    if (!vault_bridge_ready () || key_length != VAULT_KEY || nonce_length == 0)
        return NULL;
    if (gcry_cipher_open (&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0) != 0)
        return NULL;
    if (gcry_cipher_setkey (handle, key, key_length) != 0 || gcry_cipher_setiv (handle, nonce, nonce_length) != 0) {
        gcry_cipher_close (handle);
        return NULL;
    }
    return handle;
}

gboolean
vault_bridge_seal (const guint8 *key, gsize key_length,
                   const guint8 *nonce, gsize nonce_length,
                   const guint8 *plain, gsize plain_length,
                   guint8 *cipher, gsize cipher_length,
                   guint8 *tag, gsize tag_length)
{
    gcry_cipher_hd_t handle;
    gboolean ok;

    if (cipher_length != plain_length || tag_length != VAULT_TAG)
        return FALSE;
    handle = vault_bridge_cipher (key, key_length, nonce, nonce_length);
    if (handle == NULL)
        return FALSE;
    gcry_cipher_final (handle);
    ok = gcry_cipher_encrypt (handle, cipher, cipher_length, plain, plain_length) == 0
        && gcry_cipher_gettag (handle, tag, tag_length) == 0;
    gcry_cipher_close (handle);
    return ok;
}

gboolean
vault_bridge_open (const guint8 *key, gsize key_length,
                   const guint8 *nonce, gsize nonce_length,
                   const guint8 *cipher, gsize cipher_length,
                   const guint8 *tag, gsize tag_length,
                   guint8 *plain, gsize plain_length)
{
    gcry_cipher_hd_t handle;
    gboolean ok;

    if (cipher_length != plain_length || tag_length != VAULT_TAG)
        return FALSE;
    handle = vault_bridge_cipher (key, key_length, nonce, nonce_length);
    if (handle == NULL)
        return FALSE;
    gcry_cipher_final (handle);
    ok = gcry_cipher_decrypt (handle, plain, plain_length, cipher, cipher_length) == 0
        && gcry_cipher_checktag (handle, tag, tag_length) == 0;
    gcry_cipher_close (handle);
    if (!ok && plain_length > 0)
        memset (plain, 0, plain_length);
    return ok;
}

void
vault_bridge_random (guint8 *buffer, gsize length)
{
    if (vault_bridge_ready ())
        gcry_randomize (buffer, length, GCRY_STRONG_RANDOM);
    else
        g_error ("libgcrypt could not be initialised");
}
