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

uint8[] hex (string text) {
    var v = Vault.from_hex (text);
    assert (v != null);
    return v;
}

void expect_vault_error (string text, string password, int code) {
    try {
        Transfer.parse_aegis_encrypted (text, password);
    } catch (VaultError e) {
        if (e.code != code) error ("wrong error: %s", e.message);
        return;
    } catch (AccountError e) {
        error ("account error: %s", e.message);
    }
    error ("vault opened");
}

Account make (string issuer, string name, string secret, string[] tags) {
    var a = new Account ();
    a.id = Uuid.string_random ();
    a.issuer = issuer;
    a.name = name;
    a.secret = secret;
    a.set_tags (tags);
    return a;
}

void main (string[] args) {
    Test.init (ref args);
    fixtures = args.length > 1 ? args[1] : "tests/fixtures";

    Test.add_func ("/hex", () => {
        assert (Vault.to_hex ({ 0x00, 0xab, 0xff }) == "00abff");
        var v = Vault.from_hex ("00ABff");
        assert (v != null && v.length == 3 && v[1] == 0xab && v[2] == 0xff);
        assert (Vault.from_hex ("abc") == null);
        assert (Vault.from_hex ("zz") == null);
    });
    Test.add_func ("/scrypt/rfc7914", () => {
        var key = new uint8[64];
        assert (VaultBridge.scrypt ("password".data, "NaCl".data, 1024, 8, 16, key));
        assert (Vault.to_hex (key) == "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
        assert (VaultBridge.scrypt ("pleaseletmein".data, "SodiumChloride".data, 16384, 8, 1, key));
        assert (Vault.to_hex (key) == "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
        assert (!VaultBridge.scrypt ("x".data, "y".data, 1000, 8, 1, key));
        assert (!VaultBridge.scrypt ("x".data, "y".data, 1024, 16, 1, key));
    });
    Test.add_func ("/gcm/nist", () => {
        var key = hex ("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        var nonce = hex ("cafebabefacedbaddecaf888");
        var plain = hex ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        uint8[] tag;
        try {
            var cipher = Vault.encrypt (key, nonce, plain, out tag);
            assert (Vault.to_hex (cipher) == "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad");
            assert (Vault.to_hex (tag) == "b094dac5d93471bdec1a502270e3cc6c");
            var back = Vault.decrypt (key, nonce, cipher, tag);
            assert (back != null && Vault.to_hex (back) == Vault.to_hex (plain));
            cipher[5] ^= 1;
            assert (Vault.decrypt (key, nonce, cipher, tag) == null);
            cipher[5] ^= 1;
            tag[0] ^= 1;
            assert (Vault.decrypt (key, nonce, cipher, tag) == null);
        } catch (VaultError e) {
            error (e.message);
        }
    });
    Test.add_func ("/aegis/encrypted-fixture", () => {
        try {
            var r = Transfer.parse_aegis_encrypted (fixture ("aegis_vault.json"), "correct horse");
            assert (r.format == "Aegis");
            assert (r.accounts.size == 3 && r.skipped == 1);
            var gh = r.accounts[0];
            assert (gh.issuer == "GitHub" && gh.name == "alice@example.com" && gh.secret == "JBSWY3DPEHPK3PXP");
            assert (gh.tags.length == 2 && gh.tags[0] == "Work" && gh.tags[1] == "Personal");
            var bank = r.accounts[1];
            assert (bank.kind == Kind.HOTP && bank.counter == 7 && bank.algorithm == Algorithm.SHA256 && bank.digits == 8);
            assert (bank.tags.length == 1 && bank.tags[0] == "Personal");
            var steam = r.accounts[2];
            assert (steam.kind == Kind.STEAM && steam.tags.length == 1 && steam.tags[0] == "Games");
        } catch (Error e) {
            error (e.message);
        }
    });
    Test.add_func ("/aegis/detects-encrypted", () => {
        try {
            Transfer.parse (fixture ("aegis_vault.json"));
            error ("encrypted vault parsed as plain");
        } catch (AccountError e) {
            assert (e is AccountError.ENCRYPTED);
        }
    });
    Test.add_func ("/aegis/wrong-password", () => {
        expect_vault_error (fixture ("aegis_vault.json"), "correct hors", VaultError.WRONG_PASSWORD);
        expect_vault_error (fixture ("aegis_encrypted.json"), "test", VaultError.WRONG_PASSWORD);
    });
    Test.add_func ("/aegis/tampered", () => {
        string text = fixture ("aegis_vault.json");
        var parser = new Json.Parser ();
        try {
            parser.load_from_data (text);
        } catch (Error e) {
            error (e.message);
        }
        var top = parser.get_root ().get_object ();
        var db = Base64.decode (top.get_string_member ("db"));
        db[10] ^= 0x40;
        top.set_string_member ("db", Base64.encode (db));
        var gen = new Json.Generator ();
        gen.set_root (parser.get_root ());
        expect_vault_error (gen.to_data (null), "correct horse", VaultError.INVALID);
        expect_vault_error ("{\"header\":{\"slots\":[]},\"db\":\"\"}", "x", VaultError.INVALID);
        expect_vault_error ("not json", "x", VaultError.INVALID);
    });
    Test.add_func ("/aegis/slot-kinds", () => {
        string only_fingerprint = "{\"version\":1,\"header\":{\"slots\":[{\"type\":2,\"uuid\":\"u\",\"key\":\"00\",\"key_params\":{\"nonce\":\"00\",\"tag\":\"00\"}}],\"params\":{\"nonce\":\"000000000000000000000000\",\"tag\":\"00000000000000000000000000000000\"}},\"db\":\"AAAA\"}";
        expect_vault_error (only_fingerprint, "x", VaultError.UNSUPPORTED);
        string wide = fixture ("aegis_vault.json").replace ("\"r\": 8", "\"r\": 16");
        expect_vault_error (wide, "correct horse", VaultError.UNSUPPORTED);
        string huge = fixture ("aegis_vault.json").replace ("\"n\": 32768", "\"n\": 1073741824");
        expect_vault_error (huge, "correct horse", VaultError.INVALID);
    });
    Test.add_func ("/aegis/roundtrip", () => {
        var list = new Gee.ArrayList<Account> ();
        list.add (make ("GitHub", "alice", "JBSWY3DPEHPK3PXP", { "Work", "Code" }));
        list.add (make ("Bank", "bob", "GEZDGNBVGY3TQOJQ", { "work" }));
        var hotp = make ("Mail", "carol", "MFRGGZDFMZTWQ2LK", {});
        hotp.kind = Kind.HOTP;
        hotp.counter = 17;
        hotp.digits = 7;
        list.add (hotp);
        try {
            string sealed = Transfer.export_aegis_encrypted (list, "hunter2 hunter2", 1024);
            assert (!sealed.contains ("JBSWY3DPEHPK3PXP"));
            assert (!sealed.contains ("GitHub"));
            try {
                Transfer.parse (sealed);
                error ("sealed vault read as plain");
            } catch (AccountError e) {
                assert (e is AccountError.ENCRYPTED);
            }
            var r = Transfer.parse_aegis_encrypted (sealed, "hunter2 hunter2");
            assert (r.accounts.size == 3 && r.skipped == 0);
            for (int i = 0; i < 3; i++) {
                assert (r.accounts[i].same_as (list[i]));
                assert (r.accounts[i].code (1700000000) == list[i].code (1700000000));
            }
            assert (r.accounts[0].tags.length == 2 && r.accounts[0].tags[0] == "Work" && r.accounts[0].tags[1] == "Code");
            assert (r.accounts[1].tags.length == 1 && r.accounts[1].tags[0] == "Work");
            assert (r.accounts[2].counter == 17 && r.accounts[2].digits == 7 && r.accounts[2].tags.length == 0);
            expect_vault_error (sealed, "hunter2", VaultError.WRONG_PASSWORD);
            string again = Transfer.export_aegis_encrypted (list, "hunter2 hunter2", 1024);
            assert (again != sealed);
            var plain = Transfer.parse (Transfer.export_aegis (list));
            assert (plain.accounts.size == 3 && plain.accounts[0].tags.length == 2);
        } catch (Error e) {
            error (e.message);
        }
    });
    Test.run ();
}
