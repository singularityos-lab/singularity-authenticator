#pragma once

#include <glib.h>

gchar **qr_bridge_decode (const guint8 *gray, gint gray_length, gint width, gint height);
