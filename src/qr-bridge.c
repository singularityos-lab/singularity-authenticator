#include "qr-bridge.h"

#include <string.h>
#include <zbar.h>

gchar **
qr_bridge_decode (const guint8 *gray, gint gray_length, gint width, gint height)
{
    GPtrArray *found = g_ptr_array_new ();
    zbar_image_scanner_t *scanner;
    zbar_image_t *image;
    const zbar_symbol_t *symbol;
    guint8 *copy;

    if (gray == NULL || width <= 0 || height <= 0 || gray_length < width * height) {
        g_ptr_array_add (found, NULL);
        return (gchar **) g_ptr_array_free (found, FALSE);
    }

    scanner = zbar_image_scanner_create ();
    zbar_image_scanner_set_config (scanner, 0, ZBAR_CFG_ENABLE, 0);
    zbar_image_scanner_set_config (scanner, ZBAR_QRCODE, ZBAR_CFG_ENABLE, 1);

    copy = g_memdup2 (gray, (gsize) width * height);
    image = zbar_image_create ();
    zbar_image_set_format (image, zbar_fourcc ('Y', '8', '0', '0'));
    zbar_image_set_size (image, width, height);
    zbar_image_set_data (image, copy, (unsigned long) width * height, zbar_image_free_data);

    if (zbar_scan_image (scanner, image) > 0) {
        for (symbol = zbar_image_first_symbol (image); symbol != NULL; symbol = zbar_symbol_next (symbol)) {
            const char *data = zbar_symbol_get_data (symbol);
            unsigned int length = zbar_symbol_get_data_length (symbol);
            if (data != NULL && length > 0)
                g_ptr_array_add (found, g_strndup (data, length));
        }
    }

    zbar_image_destroy (image);
    zbar_image_scanner_destroy (scanner);
    g_ptr_array_add (found, NULL);
    return (gchar **) g_ptr_array_free (found, FALSE);
}
