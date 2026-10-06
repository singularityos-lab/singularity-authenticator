namespace Singularity.Apps.Authenticator {

    namespace Render {
        public const int QUIET = 4;

        public void draw (Cairo.Context cr, QrCode qr, double x, double y, double module) {
            int n = qr.size + QUIET * 2;
            cr.save ();
            if (module == Math.floor (module)) cr.set_antialias (Cairo.Antialias.NONE);
            cr.set_source_rgb (1, 1, 1);
            cr.rectangle (x, y, n * module, n * module);
            cr.fill ();
            cr.set_source_rgb (0, 0, 0);
            for (int my = 0; my < qr.size; my++) {
                int mx = 0;
                while (mx < qr.size) {
                    if (!qr.get_module (mx, my)) {
                        mx++;
                        continue;
                    }
                    int start = mx;
                    while (mx < qr.size && qr.get_module (mx, my)) mx++;
                    cr.rectangle (x + (start + QUIET) * module, y + (my + QUIET) * module, (mx - start) * module, module);
                }
            }
            cr.fill ();
            cr.restore ();
        }

        public Cairo.ImageSurface surface (QrCode qr, int module) {
            int px = (qr.size + QUIET * 2) * module;
            var s = new Cairo.ImageSurface (Cairo.Format.RGB24, px, px);
            var cr = new Cairo.Context (s);
            draw (cr, qr, 0, 0, module);
            s.flush ();
            return s;
        }

        public int module_for_size (QrCode qr, int target_px) {
            return int.max (1, target_px / (qr.size + QUIET * 2));
        }

        public void save_png (QrCode qr, int module, string path) throws Error {
            var s = surface (qr, module);
            var status = s.write_to_png (path);
            if (status != Cairo.Status.SUCCESS) throw new IOError.FAILED (_("The image could not be saved."));
        }
    }
}
