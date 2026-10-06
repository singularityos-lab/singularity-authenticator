using Singularity.Apps.Authenticator;

const string SEED1 = "12345678901234567890";
const string SEED256 = "12345678901234567890123456789012";
const string SEED512 = "1234567890123456789012345678901234567890123456789012345678901234";

void check (string label, string got, string want) {
    if (got != want) error ("%s: got %s, want %s", label, got, want);
}

void main (string[] args) {
    Test.init (ref args);

    Test.add_func ("/rfc4226/hotp", () => {
        string[] want = { "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489" };
        for (int c = 0; c < want.length; c++) check ("hotp %d".printf (c), Otp.hotp (SEED1.data, c), want[c]);
    });
    Test.add_func ("/rfc4226/truncate", () => {
        uint32[] want = { 1284755224, 1094287082, 137359152, 1726969429, 1640338314, 868254676, 1918287922, 82162583, 673399871, 645520489 };
        for (int c = 0; c < want.length; c++) assert (Otp.truncate (SEED1.data, c, Algorithm.SHA1) == want[c]);
    });
    Test.add_func ("/rfc6238/totp", () => {
        int64[] times = { 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 };
        string[] sha1 = { "94287082", "07081804", "14050471", "89005924", "69279037", "65353130" };
        string[] sha256 = { "46119246", "68084774", "67062674", "91819424", "90698825", "77737706" };
        string[] sha512 = { "90693936", "25091201", "99943326", "93441116", "38618901", "47863826" };
        for (int i = 0; i < times.length; i++) {
            check ("sha1 %s".printf (times[i].to_string ()), Otp.totp (SEED1.data, times[i], 30, 8, Algorithm.SHA1), sha1[i]);
            check ("sha256 %s".printf (times[i].to_string ()), Otp.totp (SEED256.data, times[i], 30, 8, Algorithm.SHA256), sha256[i]);
            check ("sha512 %s".printf (times[i].to_string ()), Otp.totp (SEED512.data, times[i], 30, 8, Algorithm.SHA512), sha512[i]);
        }
    });
    Test.add_func ("/totp/digits-period", () => {
        check ("6 digits", Otp.totp (SEED1.data, 59, 30, 6), "287082");
        check ("7 digits", Otp.totp (SEED1.data, 59, 30, 7), "4287082");
        check ("period 60", Otp.totp (SEED1.data, 119, 60, 6), Otp.hotp (SEED1.data, 1, 6));
        check ("period 15", Otp.totp (SEED1.data, 45, 15, 6), Otp.hotp (SEED1.data, 3, 6));
        assert (Otp.time_counter (59, 30) == 1);
        assert (Otp.time_counter (-5, 30) == 0);
        assert (Otp.seconds_left (59, 30) == 1);
        assert (Otp.seconds_left (60, 30) == 30);
        assert (Otp.seconds_left (61, 0) == 29);
    });
    Test.add_func ("/steam", () => {
        var key = Base32.decode ("JBSWY3DPEHPK3PXP");
        check ("steam 0", Otp.steam (key, 0), "VH8YJ");
        check ("steam 59", Otp.steam (key, 59), "2YXGV");
        check ("steam 1111111109", Otp.steam (key, 1111111109), "CWDGV");
        check ("steam 1700000000", Otp.steam (key, 1700000000), "2KM2P");
        check ("steam rfc seed 59", Otp.steam (SEED1.data, 59), "PV9M4");
        check ("steam rfc seed 1234567890", Otp.steam (SEED1.data, 1234567890), "VHHQY");
        string code = Otp.steam (key, 1234);
        assert (code.length == 5);
        for (int i = 0; i < code.length; i++) assert (Otp.STEAM_ALPHABET.index_of_char (code[i]) >= 0);
    });
    Test.add_func ("/account/code", () => {
        var a = new Account ();
        a.secret = Base32.encode (SEED1.data);
        a.digits = 8;
        a.algorithm = Algorithm.SHA1;
        check ("account totp", a.code (1234567890), "89005924");
        a.kind = Kind.HOTP;
        a.digits = 6;
        a.counter = 9;
        check ("account hotp", a.code (0), "520489");
        a.kind = Kind.STEAM;
        check ("account steam", a.code (59), "PV9M4");
        check ("group 6", Account.group_code ("123456"), "123 456");
        check ("group 7", Account.group_code ("1234567"), "1234 567");
        check ("group 8", Account.group_code ("12345678"), "1234 5678");
        check ("group steam", Account.group_code ("VH8YJ"), "VH8YJ");
    });
    Test.add_func ("/base32/rfc4648", () => {
        string[] plain = { "f", "fo", "foo", "foob", "fooba", "foobar" };
        string[] enc = { "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======" };
        for (int i = 0; i < plain.length; i++) {
            check ("encode " + plain[i], Base32.encode (plain[i].data, true), enc[i]);
            var d = Base32.decode (enc[i]);
            assert (d != null);
            check ("decode " + enc[i], (string) Pbkdf2.to_hex (d), Pbkdf2.to_hex (plain[i].data));
            var bare = Base32.decode (enc[i].replace ("=", "").down ());
            assert (bare != null && Pbkdf2.to_hex (bare) == Pbkdf2.to_hex (plain[i].data));
        }
        check ("no padding", Base32.encode ("foobar".data), "MZXW6YTBOI");
    });
    Test.add_func ("/base32/lenient", () => {
        var a = Base32.decode ("jbsw y3dp-ehpk 3pxp");
        var b = Base32.decode ("JBSWY3DPEHPK3PXP");
        assert (a != null && b != null && Pbkdf2.to_hex (a) == Pbkdf2.to_hex (b));
        check ("hello", (string) Pbkdf2.to_hex (b), Pbkdf2.to_hex ("Hello!\xde\xad\xbe\xef".data));
        assert (Base32.clean (" ab-cd==") == "ABCD");
    });
    Test.add_func ("/base32/invalid", () => {
        assert (Base32.decode ("") == null);
        assert (Base32.decode ("====") == null);
        assert (Base32.decode ("A") == null);
        assert (Base32.decode ("JBSWY3DP1") == null);
        assert (Base32.decode ("JBSWY3D0") == null);
        assert (Base32.decode ("JBSW!3DP") == null);
        assert (!Base32.is_valid ("89"));
        assert (Base32.is_valid ("JBSWY3DPEHPK3PXP"));
    });
    Test.add_func ("/pbkdf2/vectors", () => {
        check ("rfc6070 c1", Pbkdf2.to_hex (Pbkdf2.derive (Algorithm.SHA1, "password".data, "salt".data, 1, 20)), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
        check ("rfc6070 c2", Pbkdf2.to_hex (Pbkdf2.derive (Algorithm.SHA1, "password".data, "salt".data, 2, 20)), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        check ("rfc6070 c4096", Pbkdf2.to_hex (Pbkdf2.derive (Algorithm.SHA1, "password".data, "salt".data, 4096, 20)), "4b007901b765489abead49d926f721d065a429c1");
        check ("rfc7914 sha256", Pbkdf2.to_hex (Pbkdf2.derive (Algorithm.SHA256, "passwd".data, "salt".data, 1, 64)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");
        check ("sha512", Pbkdf2.to_hex (Pbkdf2.derive (Algorithm.SHA512, "password".data, "salt".data, 2, 64)),
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e");
    });
    Test.add_func ("/password/hash", () => {
        string h = PasswordHash.create ("correct horse", 1000);
        assert (h.has_prefix ("pbkdf2-sha256$1000$"));
        assert (PasswordHash.verify ("correct horse", h));
        assert (!PasswordHash.verify ("correct horsE", h));
        assert (!PasswordHash.verify ("", h));
        assert (h != PasswordHash.create ("correct horse", 1000));
        assert (!PasswordHash.verify ("x", "garbage"));
        assert (!PasswordHash.verify ("x", "pbkdf2-sha256$0$AAAA$AAAA"));
    });
    Test.run ();
}
