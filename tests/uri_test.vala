using Singularity.Apps.Authenticator;

Account parse (string uri) {
    try {
        return Account.parse_uri (uri);
    } catch (AccountError e) {
        error ("%s: %s", uri, e.message);
    }
}

void rejects (string uri, int code) {
    try {
        Account.parse_uri (uri);
    } catch (AccountError e) {
        if (e.code != code) error ("%s: wrong error %s", uri, e.message);
        return;
    }
    error ("%s: accepted", uri);
}

void main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/uri/google-example", () => {
        var a = parse ("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        assert (a.kind == Kind.TOTP && a.issuer == "Example" && a.name == "alice@google.com");
        assert (a.secret == "JBSWY3DPEHPK3PXP" && a.digits == 6 && a.period == 30 && a.algorithm == Algorithm.SHA1);
    });
    Test.add_func ("/uri/full", () => {
        var a = parse ("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60");
        assert (a.issuer == "ACME Co" && a.name == "john.doe@email.com");
        assert (a.algorithm == Algorithm.SHA512 && a.digits == 8 && a.period == 60);
    });
    Test.add_func ("/uri/label-forms", () => {
        var a = parse ("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP");
        assert (a.issuer == "" && a.name == "alice");
        var b = parse ("otpauth://totp/Big%20Corp%3A%20bob?secret=JBSWY3DPEHPK3PXP");
        assert (b.issuer == "Big Corp" && b.name == "bob");
        var c = parse ("otpauth://totp/Label:carol?secret=JBSWY3DPEHPK3PXP&issuer=Real+Issuer");
        assert (c.issuer == "Real Issuer" && c.name == "carol");
        var d = parse ("otpauth://totp/?secret=JBSWY3DPEHPK3PXP&issuer=OnlyIssuer");
        assert (d.issuer == "OnlyIssuer" && d.name == "");
        var e = parse ("otpauth://totp/Svc:dave%40mail.com?issuer=Svc&secret=jbsw%20y3dp%20ehpk%203pxp#frag");
        assert (e.name == "dave@mail.com" && e.secret == "JBSWY3DPEHPK3PXP");
        var f = parse ("OTPAUTH://TOTP/X:y?SECRET=JBSWY3DPEHPK3PXP&Algorithm=sha256");
        assert (f.algorithm == Algorithm.SHA256 && f.issuer == "X");
        var g = parse ("otpauth://totp/Weird:na%3Ame?secret=JBSWY3DPEHPK3PXP====");
        assert (g.issuer == "Weird" && g.name == "na:me" && g.secret == "JBSWY3DPEHPK3PXP");
    });
    Test.add_func ("/uri/hotp", () => {
        var a = parse ("otpauth://hotp/Bank:me?secret=JBSWY3DPEHPK3PXP&counter=42&digits=7");
        assert (a.kind == Kind.HOTP && a.counter == 42 && a.digits == 7);
        var b = parse ("otpauth://hotp/Bank:me?secret=JBSWY3DPEHPK3PXP");
        assert (b.kind == Kind.HOTP && b.counter == 0);
        var c = parse ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=18446744073709551615");
        assert (c.counter == uint64.MAX);
    });
    Test.add_func ("/uri/steam", () => {
        var a = parse ("otpauth://steam/Steam:gamer?secret=JBSWY3DPEHPK3PXP&issuer=Steam");
        assert (a.kind == Kind.STEAM && a.digits == 5 && a.issuer == "Steam" && a.name == "gamer");
        var b = parse ("otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&encoder=steam&digits=5");
        assert (b.kind == Kind.STEAM && b.code_digits () == 5);
        var c = parse ("otpauth://steam/gamer?secret=JBSWY3DPEHPK3PXP");
        assert (c.issuer == "Steam");
    });
    Test.add_func ("/uri/invalid", () => {
        rejects ("", AccountError.INVALID);
        rejects ("https://example.com", AccountError.INVALID);
        rejects ("otpauth://totp/x", AccountError.INVALID);
        rejects ("otpauth://totp/x?secret=", AccountError.INVALID);
        rejects ("otpauth://totp/x?secret=1234", AccountError.INVALID);
        rejects ("otpauth://yotp/x?secret=JBSWY3DPEHPK3PXP", AccountError.UNSUPPORTED);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", AccountError.UNSUPPORTED);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=4", AccountError.UNSUPPORTED);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=10", AccountError.UNSUPPORTED);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=six", AccountError.INVALID);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0", AccountError.INVALID);
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=-30", AccountError.INVALID);
        rejects ("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=-1", AccountError.INVALID);
        rejects ("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8", AccountError.UNSUPPORTED);
    });
    Test.add_func ("/uri/serialize", () => {
        var a = new Account ();
        a.issuer = "ACME Co";
        a.name = "john:doe@example.com";
        a.secret = "jbsw y3dp ehpk 3pxp";
        a.algorithm = Algorithm.SHA256;
        a.digits = 8;
        a.period = 45;
        string uri = a.to_uri ();
        assert (uri == "otpauth://totp/ACME%20Co:john%3Adoe%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=45");
        var b = parse (uri);
        assert (b.issuer == a.issuer && b.name == a.name && b.secret == "JBSWY3DPEHPK3PXP" && b.algorithm == a.algorithm && b.digits == 8 && b.period == 45);

        var h = new Account ();
        h.kind = Kind.HOTP;
        h.name = "solo";
        h.secret = "JBSWY3DPEHPK3PXP";
        h.counter = 7;
        assert (h.to_uri () == "otpauth://hotp/solo?secret=JBSWY3DPEHPK3PXP&algorithm=SHA1&digits=6&counter=7");
        var h2 = parse (h.to_uri ());
        assert (h2.kind == Kind.HOTP && h2.counter == 7 && h2.issuer == "");

        var s = new Account ();
        s.kind = Kind.STEAM;
        s.issuer = "Steam";
        s.name = "gamer";
        s.secret = "JBSWY3DPEHPK3PXP";
        assert (s.to_uri () == "otpauth://steam/Steam:gamer?secret=JBSWY3DPEHPK3PXP&issuer=Steam");
        var s2 = parse (s.to_uri ());
        assert (s2.kind == Kind.STEAM && s2.code (59) == s.code (59));

        var u = new Account ();
        u.issuer = "Café & Co";
        u.name = "zoë";
        u.secret = "JBSWY3DPEHPK3PXP";
        var u2 = parse (u.to_uri ());
        assert (u2.issuer == "Café & Co" && u2.name == "zoë");
    });
    Test.add_func ("/account/validate", () => {
        var a = new Account ();
        a.secret = "JBSWY3DPEHPK3PXP";
        assert (a.validate () == null);
        a.digits = 5;
        assert (a.validate () != null);
        a.kind = Kind.STEAM;
        assert (a.validate () == null);
        a.kind = Kind.TOTP;
        a.digits = 6;
        a.period = 0;
        assert (a.validate () != null);
        a.period = 30;
        a.secret = "not base32!";
        assert (a.validate () != null);
    });
    Test.run ();
}
