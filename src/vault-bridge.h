#pragma once

#include <glib.h>

gboolean vault_bridge_scrypt (const guint8 *password, gsize password_length,
                              const guint8 *salt, gsize salt_length,
                              guint64 n, gint r, gint p,
                              guint8 *key, gsize key_length);

gboolean vault_bridge_seal (const guint8 *key, gsize key_length,
                            const guint8 *nonce, gsize nonce_length,
                            const guint8 *plain, gsize plain_length,
                            guint8 *cipher, gsize cipher_length,
                            guint8 *tag, gsize tag_length);

gboolean vault_bridge_open (const guint8 *key, gsize key_length,
                            const guint8 *nonce, gsize nonce_length,
                            const guint8 *cipher, gsize cipher_length,
                            const guint8 *tag, gsize tag_length,
                            guint8 *plain, gsize plain_length);

void vault_bridge_random (guint8 *buffer, gsize length);
