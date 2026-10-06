using Singularity.Apps.Authenticator;

string fixtures;

string[] decode (string name) {
    try {
        return Qr.decode_file (Path.build_filename (fixtures, name));
    } catch (Error e) {
        error ("%s: %s", name, e.message);
    }
}

void main (string[] args) {
    Test.init (ref args);
    fixtures = args.length > 1 ? args[1] : "tests/fixtures";

    Test.add_func ("/qr/totp", () => {
        var codes = decode ("qr_totp.png");
        assert (codes.length == 1);
        assert (codes[0] == "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
    });
    Test.add_func ("/qr/transparent-small", () => {
        var codes = decode ("qr_alpha.png");
        assert (codes.length == 1);
        assert (codes[0] == "otpauth://hotp/Bank:carol?secret=GEZDGNBVGY3TQOJQ&counter=5");
    });
    Test.add_func ("/qr/none", () => {
        assert (decode ("no_qr.png").length == 0);
    });
    Test.add_func ("/qr/not-image", () => {
        try {
            Qr.decode_file (Path.build_filename (fixtures, "uris.txt"));
            error ("text file decoded");
        } catch (Error e) {
        }
    });
    Test.add_func ("/qr/export-roundtrip", () => {
        var a = new Account ();
        a.issuer = "Example & Co";
        a.name = "alice@example.com";
        a.secret = "JBSWY3DPEHPK3PXP";
        a.kind = Kind.TOTP;
        a.algorithm = Algorithm.SHA256;
        a.digits = 8;
        a.period = 45;
        try {
            var qr = QrCode.encode_text (a.to_uri (), EcLevel.MEDIUM);
            string path = Path.build_filename (Environment.get_tmp_dir (), "auth-qr-%u.png".printf (Random.next_int ()));
            Render.save_png (qr, Render.module_for_size (qr, 320), path);
            string[] codes = Qr.decode_file (path);
            FileUtils.remove (path);
            assert (codes.length == 1 && codes[0] == a.to_uri ());
            var back = Account.parse_uri (codes[0]);
            assert (back.same_as (a) && back.code (1700000000) == a.code (1700000000));
        } catch (Error e) {
            error (e.message);
        }
    });
    Test.add_func ("/qr/migration-screenshot", () => {
        string uri;
        try {
            FileUtils.get_contents (Path.build_filename (fixtures, "migration.txt"), out uri);
            uri = uri.strip ();
            var qr = QrCode.encode_text (uri, EcLevel.LOW);
            var shot = new Cairo.ImageSurface (Cairo.Format.RGB24, 1280, 800);
            var cr = new Cairo.Context (shot);
            var grad = new Cairo.Pattern.linear (0, 0, 1280, 800);
            grad.add_color_stop_rgb (0, 0.93, 0.94, 0.96);
            grad.add_color_stop_rgb (1, 0.80, 0.83, 0.88);
            cr.set_source (grad);
            cr.paint ();
            cr.set_source_rgb (0.2, 0.2, 0.25);
            cr.rectangle (0, 0, 1280, 56);
            cr.fill ();
            cr.set_source_rgb (0.1, 0.1, 0.1);
            cr.move_to (80, 140);
            cr.set_font_size (28);
            cr.show_text ("Transfer accounts");
            Render.draw (cr, qr, 440, 200, 5);
            shot.flush ();
            string path = Path.build_filename (Environment.get_tmp_dir (), "auth-shot-%u.png".printf (Random.next_int ()));
            shot.write_to_png (path);
            string[] codes = Qr.decode_file (path);
            FileUtils.remove (path);
            assert (codes.length == 1 && codes[0] == uri);
            var r = Migration.parse (codes[0]);
            assert (r.accounts.size == 3 && r.skipped == 1);
        } catch (Error e) {
            error (e.message);
        }
    });
    Test.run ();
}
