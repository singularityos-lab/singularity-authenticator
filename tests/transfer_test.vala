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

ImportResult import (string name) {
    try {
        return Transfer.parse (fixture (name));
    } catch (AccountError e) {
        error ("%s: %s", name, e.message);
    }
}

void rejects (string name, int code) {
    try {
        Transfer.parse (fixture (name));
    } catch (AccountError e) {
        if (e.code != code) error ("%s: wrong error %s", name, e.message);
        return;
    }
    error ("%s: accepted", name);
}

string temp_dir () {
    try {
        return DirUtils.make_tmp ("auth-XXXXXX");
    } catch (Error e) {
        error (e.message);
    }
}

void main (string[] args) {
    Test.init (ref args);
    fixtures = args.length > 1 ? args[1] : "tests/fixtures";

    Test.add_func ("/aegis/plain", () => {
        var r = import ("aegis_plain.json");
        assert (r.format == "Aegis");
        assert (r.accounts.size == 4);
        assert (r.skipped == 2);
        var gh = r.accounts[0];
        assert (gh.issuer == "GitHub" && gh.name == "alice@example.com" && gh.kind == Kind.TOTP && gh.digits == 6);
        var cloud = r.accounts[1];
        assert (cloud.algorithm == Algorithm.SHA256 && cloud.digits == 8 && cloud.period == 60);
        var bank = r.accounts[2];
        assert (bank.kind == Kind.HOTP && bank.counter == 12 && bank.algorithm == Algorithm.SHA512 && bank.digits == 7);
        var steam = r.accounts[3];
        assert (steam.kind == Kind.STEAM && steam.code_digits () == 5);
    });
    Test.add_func ("/aegis/encrypted", () => {
        rejects ("aegis_encrypted.json", AccountError.ENCRYPTED);
    });
    Test.add_func ("/aegis/broken", () => {
        rejects ("broken.json", AccountError.INVALID);
    });
    Test.add_func ("/andotp", () => {
        var r = import ("andotp.json");
        assert (r.format == "andOTP");
        assert (r.accounts.size == 4);
        assert (r.skipped == 2);
        assert (r.accounts[0].issuer == "GitLab" && r.accounts[0].name == "dev@example.com");
        assert (r.accounts[1].issuer == "Legacy Corp" && r.accounts[1].name == "old@example.com" && r.accounts[1].period == 45 && r.accounts[1].digits == 8);
        assert (r.accounts[2].kind == Kind.HOTP && r.accounts[2].issuer == "Counter" && r.accounts[2].name == "hot" && r.accounts[2].counter == 3);
        assert (r.accounts[3].kind == Kind.STEAM);
    });
    Test.add_func ("/uri-list", () => {
        var r = import ("uris.txt");
        assert (r.format == "otpauth");
        assert (r.accounts.size == 3);
        assert (r.skipped == 2);
        assert (r.accounts[1].kind == Kind.HOTP && r.accounts[1].counter == 5);
        assert (r.accounts[2].kind == Kind.STEAM);
        try {
            Transfer.parse ("\n# nothing\n");
            error ("empty list accepted");
        } catch (AccountError e) {
            assert (e is AccountError.INVALID);
        }
        try {
            Transfer.parse ("hello\nworld");
            error ("junk accepted");
        } catch (AccountError e) {
            assert (e is AccountError.INVALID);
        }
    });
    Test.add_func ("/export/roundtrip", () => {
        var original = import ("aegis_plain.json").accounts;
        try {
            var again = Transfer.parse (Transfer.export_aegis (original));
            assert (again.accounts.size == original.size && again.skipped == 0);
            var links = Transfer.parse (Transfer.export_uri_list (original));
            assert (links.accounts.size == original.size && links.skipped == 0);
            for (int i = 0; i < original.size; i++) {
                assert (again.accounts[i].same_as (original[i]));
                assert (links.accounts[i].same_as (original[i]));
                assert (again.accounts[i].code (1700000000) == original[i].code (1700000000));
                assert (links.accounts[i].code (1700000000) == original[i].code (1700000000));
                assert (links.accounts[i].counter == original[i].counter);
            }
        } catch (AccountError e) {
            error (e.message);
        }
        var empty = new Gee.ArrayList<Account> ();
        assert (Transfer.export_uri_list (empty) == "");
    });
    Test.add_func ("/store/no-secrets-on-disk", () => {
        string dir = temp_dir ();
        string file = Path.build_filename (dir, "accounts.json");
        var s = new AccountStore (file);
        var a = new Account ();
        a.id = "acc-1";
        a.issuer = "GitHub";
        a.name = "alice";
        a.kind = Kind.HOTP;
        a.algorithm = Algorithm.SHA256;
        a.digits = 7;
        a.counter = 99;
        a.secret = "JBSWY3DPEHPK3PXP";
        s.items.add (a);
        s.save ();
        string text;
        try {
            FileUtils.get_contents (file, out text);
        } catch (Error e) {
            error (e.message);
        }
        assert (!text.contains ("JBSWY3DPEHPK3PXP"));
        assert (!text.contains ("secret"));
        var s2 = new AccountStore (file);
        assert (s2.items.size == 1);
        var b = s2.items[0];
        assert (b.id == "acc-1" && b.issuer == "GitHub" && b.kind == Kind.HOTP && b.algorithm == Algorithm.SHA256 && b.digits == 7 && b.counter == 99 && b.secret == "");
        s2.forget_secrets ();
        FileUtils.remove (file);
        DirUtils.remove (dir);
    });
    Test.add_func ("/config/migrate", () => {
        string dir = temp_dir ();
        string file = Path.build_filename (dir, "c.json");
        try {
            FileUtils.set_contents (file, "{ \"lock\": \"keyring\", \"lock_minutes\": 12, \"favicons\": false, \"clear_clipboard\": true }");
        } catch (Error e) {
            assert_not_reached ();
        }
        var c = new Config (file);
        assert (c.lock_mode == LockMode.KEYRING && c.lock_minutes == 12 && !c.favicons && c.clear_clipboard);
        assert (!FileUtils.test (file, FileTest.EXISTS) && FileUtils.test (file + ".migrated", FileTest.EXISTS));
        c.lock_minutes = 500;
        var d = new Config (file);
        assert (d.lock_mode == LockMode.KEYRING && d.lock_minutes == 120 && !d.favicons);
        d.settings.reset ("lock-mode");
        assert (c.lock_mode == LockMode.NONE);
        FileUtils.remove (file + ".migrated");
        DirUtils.remove (dir);
    });
    Test.run ();
}
