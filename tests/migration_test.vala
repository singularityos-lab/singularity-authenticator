using Singularity.Apps.Authenticator;

string fixtures;

string fixture (string name) {
    string text;
    try {
        FileUtils.get_contents (Path.build_filename (fixtures, name), out text);
    } catch (Error e) {
        error ("fixture %s: %s", name, e.message);
    }
    return text;
}

void rejects (string uri) {
    try {
        Migration.parse (uri);
    } catch (AccountError e) {
        assert (e is AccountError.INVALID);
        return;
    }
    error ("accepted %s", uri);
}

uint8[] cat (uint8[] a, uint8[] b) {
    var r = new uint8[a.length + b.length];
    Memory.copy (r, a, a.length);
    Memory.copy ((uint8*) r + a.length, b, b.length);
    return r;
}

uint8[] varint (uint64 v) {
    uint8[] out_bytes = {};
    do {
        uint8 b = (uint8) (v & 0x7f);
        v >>= 7;
        if (v != 0) b |= 0x80;
        out_bytes += b;
    } while (v != 0);
    return out_bytes;
}

uint8[] field_bytes (uint num, uint8[] payload) {
    return cat (cat (varint ((num << 3) | 2), varint (payload.length)), payload);
}

uint8[] field_varint (uint num, uint64 value) {
    return cat (varint (num << 3), varint (value));
}

void main (string[] args) {
    Test.init (ref args);
    fixtures = args.length > 1 ? args[1] : "tests/fixtures";

    Test.add_func ("/proto/varint", () => {
        try {
            var r = new ProtoReader ({ 0x96, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 });
            assert (r.varint () == 150);
            assert (r.varint () == uint64.MAX);
            assert (r.at_end ());
        } catch (ProtoError e) {
            error (e.message);
        }
        try {
            new ProtoReader ({ 0x80, 0x80 }).varint ();
            error ("truncated varint accepted");
        } catch (ProtoError e) {
            assert (e is ProtoError.TRUNCATED);
        }
        try {
            new ProtoReader ({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02 }).varint ();
            error ("overflow accepted");
        } catch (ProtoError e) {
            assert (e is ProtoError.MALFORMED);
        }
        try {
            new ProtoReader ({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x81, 0x01 }).varint ();
            error ("long varint accepted");
        } catch (ProtoError e) {
            assert (e is ProtoError.MALFORMED);
        }
    });
    Test.add_func ("/proto/fields", () => {
        var data = cat (cat (field_bytes (2, "hi".data), field_varint (3, 7)), { 0x0d, 1, 2, 3, 4, 0x09, 1, 2, 3, 4, 5, 6, 7, 8 });
        try {
            var r = new ProtoReader (data);
            uint field;
            WireType wire;
            assert (r.next (out field, out wire) && field == 2 && wire == WireType.BYTES);
            assert (r.text () == "hi");
            assert (r.next (out field, out wire) && field == 3 && wire == WireType.VARINT);
            assert (r.varint () == 7);
            assert (r.next (out field, out wire) && field == 1 && wire == WireType.FIXED32);
            r.skip (wire);
            assert (r.next (out field, out wire) && field == 1 && wire == WireType.FIXED64);
            r.skip (wire);
            assert (!r.next (out field, out wire));
        } catch (ProtoError e) {
            error (e.message);
        }
        string[] broken = { "0b", "120561", "00", "0d0102", "1202fffe" };
        foreach (string b in broken) {
            try {
                var r = new ProtoReader (Vault.from_hex (b));
                uint field;
                WireType wire;
                while (r.next (out field, out wire)) {
                    if (wire == WireType.BYTES) r.text ();
                    else r.skip (wire);
                }
                error ("broken message accepted");
            } catch (ProtoError e) {
            }
        }
    });
    Test.add_func ("/migration/fixture", () => {
        try {
            string uri = fixture ("migration.txt").strip ();
            assert (Migration.is_migration (uri));
            var r = Migration.parse (uri);
            assert (r.format == "Google Authenticator");
            assert (r.accounts.size == 3 && r.skipped == 1);
            assert (r.batch_size == 2 && r.batch_index == 1);
            var gh = r.accounts[0];
            assert (gh.issuer == "GitHub" && gh.name == "alice@example.com");
            assert (gh.kind == Kind.TOTP && gh.algorithm == Algorithm.SHA1 && gh.digits == 6 && gh.period == 30);
            assert (gh.secret == Base32.encode ({ 'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef }));
            assert (gh.secret == "JBSWY3DPEHPK3PXP");
            var bank = r.accounts[1];
            assert (bank.issuer == "Bänk" && bank.name == "bob");
            assert (bank.kind == Kind.HOTP && bank.algorithm == Algorithm.SHA256 && bank.digits == 8 && bank.counter == 42);
            var carol = r.accounts[2];
            assert (carol.issuer == "Work" && carol.name == "carol" && carol.kind == Kind.TOTP && carol.algorithm == Algorithm.SHA512);
            assert (carol.code (59) == Otp.totp (Base32.decode (carol.secret), 59, 30, 6, Algorithm.SHA512));
        } catch (AccountError e) {
            error (e.message);
        }
    });
    Test.add_func ("/migration/transfer", () => {
        try {
            var r = Transfer.parse (fixture ("migration.txt"));
            assert (r.accounts.size == 3 && r.skipped == 1);
            var list = Transfer.parse ("otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP\n" + fixture ("migration.txt"));
            assert (list.accounts.size == 4 && list.skipped == 1);
        } catch (AccountError e) {
            error (e.message);
        }
        try {
            Account.parse_uri (fixture ("migration.txt"));
            error ("single parser took a migration link");
        } catch (AccountError e) {
            assert (e is AccountError.UNSUPPORTED);
        }
    });
    Test.add_func ("/migration/encodings", () => {
        var otp = cat (cat (cat (field_bytes (1, "12345678901234567890".data), field_bytes (2, "dave".data)), field_bytes (3, "Mail".data)), field_varint (6, 2));
        var payload = field_bytes (1, otp);
        string b64 = Base64.encode (payload);
        string[] forms = {
            "otpauth-migration://offline?data=" + Uri.escape_string (b64, null, false),
            "OTPAUTH-MIGRATION://offline?data=" + b64.replace ("=", ""),
            "otpauth-migration://offline?data=" + b64.replace ("+", "-").replace ("/", "_"),
            "otpauth-migration://offline?foo=1&data=" + b64 + "#x"
        };
        foreach (string f in forms) {
            try {
                var r = Migration.parse (f);
                assert (r.accounts.size == 1 && r.accounts[0].issuer == "Mail" && r.accounts[0].name == "dave");
                assert (r.accounts[0].secret == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
                assert (r.batch_size == 1);
            } catch (AccountError e) {
                error ("%s: %s", f, e.message);
            }
        }
    });
    Test.add_func ("/migration/rejects", () => {
        rejects ("otpauth-migration://offline");
        rejects ("otpauth-migration://offline?data=");
        rejects ("otpauth-migration://offline?data=%%%");
        rejects ("otpauth-migration://offline?data=CgU");
        rejects ("otpauth-migration://offline?data=" + Base64.encode (field_varint (2, 1)));
        rejects ("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP");
        try {
            var only_bad = field_bytes (1, cat (field_bytes (1, "abc".data), field_varint (4, 4)));
            var r = Migration.decode (only_bad);
            assert (r.accounts.size == 0 && r.skipped == 1);
            var no_secret = field_bytes (1, field_bytes (2, "x".data));
            r = Migration.decode (no_secret);
            assert (r.accounts.size == 0 && r.skipped == 1);
            var wrong_digits = field_bytes (1, cat (field_bytes (1, "abc".data), field_varint (5, 9)));
            assert (Migration.decode (wrong_digits).skipped == 1);
        } catch (AccountError e) {
            error (e.message);
        }
    });
    Test.run ();
}
