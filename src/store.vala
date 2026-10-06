namespace Singularity.Apps.Authenticator {

    public enum LockMode {
        NONE,
        PASSWORD,
        KEYRING;

        public string to_id () {
            switch (this) {
                case PASSWORD: return "password";
                case KEYRING: return "keyring";
                default: return "none";
            }
        }

        public static LockMode from_id (string id) {
            if (id == "password") return PASSWORD;
            if (id == "keyring") return KEYRING;
            return NONE;
        }
    }

    public class Config : Object {
        public GLib.Settings settings { get; private set; }

        public LockMode lock_mode {
            get { return LockMode.from_id (settings.get_string ("lock-mode")); }
            set { settings.set_string ("lock-mode", value.to_id ()); }
        }

        public int lock_minutes {
            get { return settings.get_int ("lock-minutes"); }
            set { settings.set_int ("lock-minutes", value.clamp (1, 120)); }
        }

        public bool favicons {
            get { return settings.get_boolean ("download-icons"); }
            set { settings.set_boolean ("download-icons", value); }
        }

        public bool clear_clipboard {
            get { return settings.get_boolean ("clear-clipboard"); }
            set { settings.set_boolean ("clear-clipboard", value); }
        }

        public Config (string? legacy_file = null) {
            settings = new GLib.Settings ("dev.sinty.authenticator");
            migrate (legacy_file ?? Path.build_filename (Environment.get_user_config_dir (), "singularity", "authenticator.json"));
        }

        private void migrate (string path) {
            if (!FileUtils.test (path, FileTest.EXISTS)) return;
            try {
                var parser = new Json.Parser ();
                parser.load_from_file (path);
                var root = parser.get_root ();
                if (root != null && root.get_node_type () == Json.NodeType.OBJECT) {
                    var o = root.get_object ();
                    lock_mode = LockMode.from_id (o.get_string_member_with_default ("lock", "none"));
                    lock_minutes = (int) o.get_int_member_with_default ("lock_minutes", 5);
                    favicons = o.get_boolean_member_with_default ("favicons", true);
                    clear_clipboard = o.get_boolean_member_with_default ("clear_clipboard", true);
                    GLib.Settings.sync ();
                }
                FileUtils.rename (path, path + ".migrated");
            } catch (Error e) {
                warning ("authenticator: %s", e.message);
            }
        }
    }

    public class AccountStore : Object {
        public Gee.ArrayList<Account> items = new Gee.ArrayList<Account> ();
        private string path;
        public signal void changed ();

        public AccountStore (string? file = null) {
            path = file ?? Path.build_filename (Environment.get_user_data_dir (), "singularity-authenticator", "accounts.json");
            load ();
        }

        private void load () {
            items.clear ();
            if (!FileUtils.test (path, FileTest.EXISTS)) return;
            try {
                var parser = new Json.Parser ();
                parser.load_from_file (path);
                var root = parser.get_root ();
                if (root == null || root.get_node_type () != Json.NodeType.ARRAY) return;
                foreach (var node in root.get_array ().get_elements ()) {
                    if (node.get_node_type () != Json.NodeType.OBJECT) continue;
                    var a = Account.from_meta_json (node.get_object ());
                    if (a != null) items.add (a);
                }
            } catch (Error e) {
                warning ("authenticator: %s", e.message);
            }
        }

        public void save () {
            var arr = new Json.Array ();
            foreach (var a in items) arr.add_element (a.to_meta_json ());
            var root = new Json.Node (Json.NodeType.ARRAY);
            root.set_array (arr);
            var gen = new Json.Generator ();
            gen.pretty = true;
            gen.set_root (root);
            try {
                DirUtils.create_with_parents (Path.get_dirname (path), 0700);
                FileUtils.set_contents (path, gen.to_data (null));
                FileUtils.chmod (path, 0600);
            } catch (Error e) {
                warning ("authenticator: %s", e.message);
            }
            changed ();
        }

        public Account? find (string id) {
            foreach (var a in items) if (a.id == id) return a;
            return null;
        }

        public Account? find_same (Account other) {
            foreach (var a in items) if (a.secret != "" && a.same_as (other)) return a;
            return null;
        }

        public Gee.List<Account> sorted () {
            var list = new Gee.ArrayList<Account> ();
            list.add_all (items);
            list.sort ((a, b) => {
                int c = a.title ().collate (b.title ());
                return c != 0 ? c : a.subtitle ().collate (b.subtitle ());
            });
            return list;
        }

        public string[] all_tags () {
            var seen = new Gee.HashMap<string, string> ();
            foreach (var a in items) {
                foreach (string t in a.tags) {
                    if (!seen.has_key (t.casefold ())) seen[t.casefold ()] = t;
                }
            }
            var list = new Gee.ArrayList<string> ();
            list.add_all (seen.values);
            list.sort ((a, b) => a.collate (b));
            return list.to_array ();
        }

        public void rename_tag (string from, string to) {
            string name = Account.clean_tag (to);
            if (name == "") return;
            foreach (var a in items) {
                if (!a.has_tag (from)) continue;
                string[] next = {};
                foreach (string t in a.tags) next += t.casefold () == from.casefold () ? name : t;
                a.set_tags (next);
            }
            save ();
        }

        public void remove_tag (string tag) {
            foreach (var a in items) {
                if (!a.has_tag (tag)) continue;
                string[] next = {};
                foreach (string t in a.tags) if (t.casefold () != tag.casefold ()) next += t;
                a.tags = next;
            }
            save ();
        }

        public async void unlock_secrets () throws Error {
            if (items.size > 0 && !(yield Keyring.unlock_default ())) {
                throw new KeyringError.LOCKED (_("The keyring is locked."));
            }
            foreach (var a in items) {
                string? s = yield Keyring.lookup (a.id);
                a.secret = s ?? "";
                a.secret_missing = s == null || Base32.decode (s) == null;
            }
            changed ();
        }

        public void forget_secrets () {
            foreach (var a in items) a.secret = "";
            changed ();
        }

        public async void put (Account a) throws Error {
            if (a.id == "") a.id = Uuid.string_random ();
            if (a.added == 0) a.added = new DateTime.now_utc ().to_unix ();
            yield Keyring.store (a);
            a.secret_missing = false;
            for (int i = 0; i < items.size; i++) {
                if (items[i].id == a.id) {
                    items[i] = a;
                    save ();
                    return;
                }
            }
            items.add (a);
            save ();
        }

        public void update_meta (Account a) {
            save ();
        }

        public async void remove (Account a) {
            for (int i = 0; i < items.size; i++) {
                if (items[i].id == a.id) {
                    items.remove_at (i);
                    break;
                }
            }
            save ();
            yield Keyring.remove (a.id);
        }
    }
}
