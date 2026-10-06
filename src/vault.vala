namespace Singularity.Apps.Authenticator {

    public errordomain VaultError {
        WRONG_PASSWORD,
        INVALID,
        UNSUPPORTED,
        FAILED
    }

    namespace Vault {
        public const uint64 DEFAULT_N = 32768;
        public const uint64 MAX_N = 262144;
        private const int KEY = 32;
        private const int NONCE = 12;
        private const int TAG = 16;
        private const int SALT = 32;
        private const int PASSWORD_SLOT = 1;

        public uint8[] random_bytes (int n) {
            var buf = new uint8[n];
            VaultBridge.random (buf);
            return buf;
        }

        public string to_hex (uint8[] data) {
            var sb = new StringBuilder.sized (data.length * 2);
            foreach (uint8 b in data) sb.append_printf ("%02x", b);
            return sb.str;
        }

        public uint8[]? from_hex (string text) {
            string t = text.strip ();
            if (t.length % 2 != 0) return null;
            var out_bytes = new uint8[t.length / 2];
            for (int i = 0; i < out_bytes.length; i++) {
                int hi = t[2 * i].xdigit_value (), lo = t[2 * i + 1].xdigit_value ();
                if (hi < 0 || lo < 0) return null;
                out_bytes[i] = (uint8) ((hi << 4) | lo);
            }
            return out_bytes;
        }

        public uint8[] derive (string password, uint8[] salt, uint64 n, int r, int p) throws VaultError {
            if (r != 8) throw new VaultError.UNSUPPORTED (_("This backup uses key settings that are not supported."));
            if (n < 2 || n > MAX_N || (n & (n - 1)) != 0 || p < 1 || p > 16) throw new VaultError.INVALID (_("The backup has invalid key settings."));
            var key = new uint8[KEY];
            if (!VaultBridge.scrypt (password.data, salt, n, r, p, key)) throw new VaultError.FAILED (_("The password could not be processed."));
            return key;
        }

        public uint8[] encrypt (uint8[] key, uint8[] nonce, uint8[] plain, out uint8[] tag) throws VaultError {
            var cipher = new uint8[plain.length];
            tag = new uint8[TAG];
            if (!VaultBridge.seal (key, nonce, plain, cipher, tag)) throw new VaultError.FAILED (_("Encryption failed."));
            return cipher;
        }

        public uint8[]? decrypt (uint8[] key, uint8[] nonce, uint8[] cipher, uint8[] tag) {
            if (key.length != KEY || tag.length != TAG || nonce.length == 0) return null;
            var plain = new uint8[cipher.length];
            if (!VaultBridge.open (key, nonce, cipher, tag, plain)) return null;
            return plain;
        }

        private void add_params (Json.Builder b, uint8[] nonce, uint8[] tag) {
            b.begin_object ();
            b.set_member_name ("nonce").add_string_value (to_hex (nonce));
            b.set_member_name ("tag").add_string_value (to_hex (tag));
            b.end_object ();
        }

        public string seal (string db_json, string password, uint64 n = DEFAULT_N) throws VaultError {
            var master = random_bytes (KEY);
            var salt = random_bytes (SALT);
            var slot_key = derive (password, salt, n, 8, 1);
            var slot_nonce = random_bytes (NONCE);
            uint8[] slot_tag;
            var wrapped = encrypt (slot_key, slot_nonce, master, out slot_tag);
            var db_nonce = random_bytes (NONCE);
            uint8[] db_tag;
            var db = encrypt (master, db_nonce, db_json.data, out db_tag);
            Memory.set (master, 0, master.length);
            Memory.set (slot_key, 0, slot_key.length);

            var b = new Json.Builder ();
            b.begin_object ();
            b.set_member_name ("version").add_int_value (1);
            b.set_member_name ("header");
            b.begin_object ();
            b.set_member_name ("slots");
            b.begin_array ();
            b.begin_object ();
            b.set_member_name ("type").add_int_value (PASSWORD_SLOT);
            b.set_member_name ("uuid").add_string_value (Uuid.string_random ());
            b.set_member_name ("key").add_string_value (to_hex (wrapped));
            b.set_member_name ("key_params");
            add_params (b, slot_nonce, slot_tag);
            b.set_member_name ("n").add_int_value ((int64) n);
            b.set_member_name ("r").add_int_value (8);
            b.set_member_name ("p").add_int_value (1);
            b.set_member_name ("salt").add_string_value (to_hex (salt));
            b.set_member_name ("repaired").add_boolean_value (true);
            b.set_member_name ("is_backup").add_boolean_value (false);
            b.end_object ();
            b.end_array ();
            b.set_member_name ("params");
            add_params (b, db_nonce, db_tag);
            b.end_object ();
            b.set_member_name ("db").add_string_value (Base64.encode (db));
            b.end_object ();
            var gen = new Json.Generator ();
            gen.pretty = true;
            gen.set_root (b.get_root ());
            return gen.to_data (null);
        }

        private uint8[] hex_member (Json.Object o, string name, int length = -1) throws VaultError {
            uint8[]? v = null;
            if (o.has_member (name) && o.get_member (name).get_value_type () == typeof (string)) v = from_hex (o.get_string_member (name));
            if (v == null || (length >= 0 && v.length != length)) throw new VaultError.INVALID (_("The backup is damaged."));
            return v;
        }

        private int64 int_member (Json.Object o, string name) throws VaultError {
            if (!o.has_member (name) || o.get_member (name).get_value_type () != typeof (int64)) throw new VaultError.INVALID (_("The backup is damaged."));
            return o.get_int_member (name);
        }

        private Json.Object object_member (Json.Object o, string name) throws VaultError {
            if (!o.has_member (name) || o.get_member (name).get_node_type () != Json.NodeType.OBJECT) throw new VaultError.INVALID (_("The backup is damaged."));
            return o.get_object_member (name);
        }

        public string open (string text, string password) throws VaultError {
            var parser = new Json.Parser ();
            try {
                parser.load_from_data (text);
            } catch (Error e) {
                throw new VaultError.INVALID (_("The file is not valid JSON."));
            }
            var root = parser.get_root ();
            if (root == null || root.get_node_type () != Json.NodeType.OBJECT) throw new VaultError.INVALID (_("This is not an Aegis backup."));
            var top = root.get_object ();
            var header = object_member (top, "header");
            if (!header.has_member ("slots") || header.get_member ("slots").get_node_type () != Json.NodeType.ARRAY) {
                throw new VaultError.INVALID (_("This backup is not encrypted."));
            }
            var params = object_member (header, "params");
            var db_nonce = hex_member (params, "nonce", NONCE);
            var db_tag = hex_member (params, "tag", TAG);
            if (!top.has_member ("db") || top.get_member ("db").get_value_type () != typeof (string)) throw new VaultError.INVALID (_("The backup is damaged."));
            var db = Base64.decode (top.get_string_member ("db"));

            bool any_password = false;
            foreach (var node in header.get_array_member ("slots").get_elements ()) {
                if (node.get_node_type () != Json.NodeType.OBJECT) continue;
                var slot = node.get_object ();
                if (!slot.has_member ("type") || slot.get_member ("type").get_value_type () != typeof (int64) || slot.get_int_member ("type") != PASSWORD_SLOT) continue;
                any_password = true;
                var salt = hex_member (slot, "salt");
                var wrapped = hex_member (slot, "key", KEY);
                var key_params = object_member (slot, "key_params");
                var key = derive (password, salt, (uint64) int_member (slot, "n"), (int) int_member (slot, "r"), (int) int_member (slot, "p"));
                var master = decrypt (key, hex_member (key_params, "nonce"), wrapped, hex_member (key_params, "tag", TAG));
                Memory.set (key, 0, key.length);
                if (master == null) continue;
                var plain = decrypt (master, db_nonce, db, db_tag);
                Memory.set (master, 0, master.length);
                if (plain == null) throw new VaultError.INVALID (_("The backup is damaged."));
                var buf = new uint8[plain.length + 1];
                Memory.copy (buf, plain, plain.length);
                string result = ((string) buf).dup ();
                Memory.set (buf, 0, buf.length);
                Memory.set (plain, 0, plain.length);
                if (!result.validate ()) throw new VaultError.INVALID (_("The backup is damaged."));
                return result;
            }
            if (!any_password) throw new VaultError.UNSUPPORTED (_("This backup can only be opened with a fingerprint on the phone that made it. Export it again from Aegis with a password."));
            throw new VaultError.WRONG_PASSWORD (_("The password is not correct."));
        }
    }
}
