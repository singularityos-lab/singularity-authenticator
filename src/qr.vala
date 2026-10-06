namespace Singularity.Apps.Authenticator {

    namespace Qr {
        public const bool AVAILABLE = true;

        public uint8[] to_gray (Gdk.Pixbuf pixbuf) {
            int w = pixbuf.width, h = pixbuf.height, stride = pixbuf.rowstride, n = pixbuf.n_channels;
            bool alpha = pixbuf.has_alpha;
            unowned uint8[] px = pixbuf.get_pixels_with_length ();
            var gray = new uint8[w * h];
            for (int y = 0; y < h; y++) {
                for (int x = 0; x < w; x++) {
                    int i = y * stride + x * n;
                    int r = px[i], g = px[i + 1], b = px[i + 2];
                    int lum = (r * 299 + g * 587 + b * 114) / 1000;
                    if (alpha) {
                        int a = px[i + 3];
                        lum = (lum * a + 255 * (255 - a)) / 255;
                    }
                    gray[y * w + x] = (uint8) lum;
                }
            }
            return gray;
        }

        public string[] decode_pixbuf (Gdk.Pixbuf source) {
            var pixbuf = source;
            if (pixbuf.n_channels < 3) return {};
            int longest = int.max (pixbuf.width, pixbuf.height);
            if (longest > 2400) {
                double k = 2400.0 / longest;
                pixbuf = pixbuf.scale_simple ((int) (pixbuf.width * k), (int) (pixbuf.height * k), Gdk.InterpType.BILINEAR);
            }
            var found = QrBridge.decode (to_gray (pixbuf), pixbuf.width, pixbuf.height);
            if (found.length == 0 && longest < 400) {
                var big = pixbuf.scale_simple (pixbuf.width * 3, pixbuf.height * 3, Gdk.InterpType.NEAREST);
                found = QrBridge.decode (to_gray (big), big.width, big.height);
            }
            return found;
        }

        public string[] decode_file (string path) throws Error {
            var pixbuf = new Gdk.Pixbuf.from_file (path);
            var t = pixbuf.apply_embedded_orientation ();
            return decode_pixbuf (t ?? pixbuf);
        }
    }
}
