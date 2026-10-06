namespace Singularity.Apps.Authenticator {

    public errordomain AccountError {
        INVALID,
        UNSUPPORTED,
        ENCRYPTED
    }

    public class Account : Object {
        public string id = "";
        public string issuer = "";
        public string name = "";
        public Kind kind = Kind.TOTP;
        public Algorithm algorithm = Algorithm.SHA1;
        public int digits = 6;
        public int period = 30;
        public uint64 counter = 0;
        public string secret = "";
        public int64 added;
        public bool secret_missing;
        public bool favorite;
        public string[] tags = {};

        public string title () {
            if (issuer != "") return issuer;
            if (name != "") return name;
            return _("Unnamed Account");
        }

        public string subtitle () {
            return issuer != "" ? name : "";
        }

        public int code_digits () {
            return kind == Kind.STEAM ? 5 : digits;
        }

        public int code_period () {
            return kind == Kind.STEAM ? 30 : period;
        }

        public string? code (int64 unix_time) {
            var key = Base32.decode (secret);
            if (key == null) return null;
            switch (kind) {
                case Kind.HOTP: return Otp.hotp (key, counter, digits, algorithm);
                case Kind.STEAM: return Otp.steam (key, unix_time);
                default: return Otp.totp (key, unix_time, period, digits, algorithm);
            }
        }

        public static string group_code (string code) {
            if (code.length < 6) return code;
            int half = code.length / 2 + (code.length == 7 ? 1 : 0);
            if (code.length == 8) half = 4;
            return code.substring (0, half) + " " + code.substring (half);
        }

        public string? validate () {
            if (Base32.decode (secret) == null) return _("The secret key is not valid. It uses the letters A to Z and the digits 2 to 7.");
            if (kind != Kind.STEAM && (digits < 6 || digits > 8)) return _("Codes must have 6, 7 or 8 digits.");
            if (kind == Kind.TOTP && (period < 1 || period > 3600)) return _("The period must be between 1 second and 1 hour.");
            return null;
        }

        public static string clean_tag (string text) {
            var sb = new StringBuilder ();
            bool space = false;
            unichar c;
            int i = 0;
            while (text.get_next_char (ref i, out c)) {
                if (c.isspace () || c == ',') {
                    space = sb.len > 0;
                    continue;
                }
                if (c.iscntrl ()) continue;
                if (space) sb.append_c (' ');
                space = false;
                sb.append_unichar (c);
            }
            string t = sb.str;
            if (t.char_count () > 32) t = t.substring (0, t.index_of_nth_char (32));
            return t;
        }

        public void set_tags (string[] list) {
            string[] result = {};
            foreach (string raw in list) {
                string t = clean_tag (raw);
                if (t == "") continue;
                bool dup = false;
                foreach (string have in result) if (have.casefold () == t.casefold ()) dup = true;
                if (!dup && result.length < 20) result += t;
            }
            tags = result;
        }

        public void set_tags_text (string text) {
            set_tags (text.split (","));
        }

        public string tags_text () {
            return string.joinv (", ", tags);
        }

        public bool has_tag (string tag) {
            foreach (string t in tags) if (t.casefold () == tag.casefold ()) return true;
            return false;
        }

        public bool same_as (Account other) {
            return Base32.clean (secret) == Base32.clean (other.secret) && kind == other.kind && issuer.down () == other.issuer.down () && name.down () == other.name.down ();
        }

        public Account copy () {
            var a = new Account ();
            a.id = id;
            a.issuer = issuer;
            a.name = name;
            a.kind = kind;
            a.algorithm = algorithm;
            a.digits = digits;
            a.period = period;
            a.counter = counter;
            a.secret = secret;
            a.added = added;
            a.secret_missing = secret_missing;
            a.favorite = favorite;
            a.tags = tags;
            return a;
        }

        public Json.Node to_meta_json () {
            var b = new Json.Builder ();
            b.begin_object ();
            b.set_member_name ("id").add_string_value (id);
            b.set_member_name ("issuer").add_string_value (issuer);
            b.set_member_name ("name").add_string_value (name);
            b.set_member_name ("type").add_string_value (kind.to_id ());
            b.set_member_name ("algorithm").add_string_value (algorithm.to_id ());
            b.set_member_name ("digits").add_int_value (digits);
            b.set_member_name ("period").add_int_value (period);
            b.set_member_name ("counter").add_int_value ((int64) counter);
            b.set_member_name ("added").add_int_value (added);
            if (favorite) b.set_member_name ("favorite").add_boolean_value (true);
            b.set_member_name ("tags");
            b.begin_array ();
            foreach (string t in tags) b.add_string_value (t);
            b.end_array ();
            b.end_object ();
            return b.get_root ();
        }

        public static Account? from_meta_json (Json.Object o) {
            string? id = o.get_string_member_with_default ("id", "");
            if (id == null || id == "") return null;
            var a = new Account ();
            a.id = id;
            a.issuer = o.get_string_member_with_default ("issuer", "");
            a.name = o.get_string_member_with_default ("name", "");
            a.kind = Kind.from_id (o.get_string_member_with_default ("type", "totp")) ?? Kind.TOTP;
            a.algorithm = Algorithm.from_id (o.get_string_member_with_default ("algorithm", "SHA1")) ?? Algorithm.SHA1;
            a.digits = (int) o.get_int_member_with_default ("digits", 6);
            a.period = (int) o.get_int_member_with_default ("period", 30);
            a.counter = (uint64) int64.max (0, o.get_int_member_with_default ("counter", 0));
            a.added = o.get_int_member_with_default ("added", 0);
            a.favorite = o.get_boolean_member_with_default ("favorite", false);
            if (o.has_member ("tags") && o.get_member ("tags").get_node_type () == Json.NodeType.ARRAY) {
                string[] found = {};
                foreach (var node in o.get_array_member ("tags").get_elements ()) {
                    if (node.get_value_type () == typeof (string)) found += node.get_string ();
                }
                a.set_tags (found);
            }
            return a;
        }

        private static string decode_component (string text, bool plus_is_space) {
            string s = plus_is_space ? text.replace ("+", " ") : text;
            return Uri.unescape_string (s) ?? s;
        }

        public static Account parse_uri (string text) throws AccountError {
            string uri = text.strip ();
            int sep = uri.index_of ("://");
            if (sep <= 0) throw new AccountError.INVALID (_("This is not an otpauth:// link."));
            string scheme = uri.substring (0, sep).down ();
            if (scheme == "otpauth-migration") {
                throw new AccountError.UNSUPPORTED (_("This link holds accounts exported from Google Authenticator. Import it to add all of them."));
            }
            if (scheme != "otpauth") throw new AccountError.INVALID (_("This is not an otpauth:// link."));
            string rest = uri.substring (sep + 3);
            string query = "";
            int q = rest.index_of_char ('?');
            if (q >= 0) {
                query = rest.substring (q + 1);
                rest = rest.substring (0, q);
            }
            int hash = query.index_of_char ('#');
            if (hash >= 0) query = query.substring (0, hash);
            string type = rest;
            string label = "";
            int slash = rest.index_of_char ('/');
            if (slash >= 0) {
                type = rest.substring (0, slash);
                label = decode_component (rest.substring (slash + 1), false);
            }
            var kind = Kind.from_id (type);
            if (kind == null) throw new AccountError.UNSUPPORTED (_("The code type “%s” is not supported.").printf (type));

            var a = new Account ();
            a.kind = kind;
            string label_issuer = "";
            int colon = label.index_of_char (':');
            if (colon >= 0) {
                label_issuer = label.substring (0, colon).strip ();
                a.name = label.substring (colon + 1).strip ();
            } else {
                a.name = label.strip ();
            }

            string? secret = null;
            string? issuer = null;
            bool have_counter = false;
            foreach (string pair in query.split ("&")) {
                if (pair == "") continue;
                int eq = pair.index_of_char ('=');
                string key = (eq >= 0 ? pair.substring (0, eq) : pair).down ();
                string raw = eq >= 0 ? pair.substring (eq + 1) : "";
                switch (key) {
                    case "secret":
                        secret = decode_component (raw, false);
                        break;
                    case "issuer":
                        issuer = decode_component (raw, true).strip ();
                        break;
                    case "algorithm":
                        var alg = Algorithm.from_id (decode_component (raw, false));
                        if (alg == null) throw new AccountError.UNSUPPORTED (_("The algorithm “%s” is not supported.").printf (raw));
                        a.algorithm = alg;
                        break;
                    case "digits":
                        int64 d;
                        if (!int64.try_parse (raw, out d)) throw new AccountError.INVALID (_("The number of digits is not valid."));
                        a.digits = (int) d.clamp (0, 100);
                        break;
                    case "period":
                        int64 p;
                        if (!int64.try_parse (raw, out p) || p <= 0 || p > 3600) throw new AccountError.INVALID (_("The period is not valid."));
                        a.period = (int) p;
                        break;
                    case "counter":
                        uint64 c = 0;
                        if (raw == "" || !all_digits (raw) || !uint64.try_parse (raw, out c)) throw new AccountError.INVALID (_("The counter is not valid."));
                        a.counter = c;
                        have_counter = true;
                        break;
                    case "encoder":
                        if (decode_component (raw, false).down () == "steam") a.kind = Kind.STEAM;
                        break;
                    default:
                        break;
                }
            }
            if (secret == null || Base32.clean (secret) == "") throw new AccountError.INVALID (_("The link has no secret key."));
            if (Base32.decode (secret) == null) throw new AccountError.INVALID (_("The secret key in the link is not valid."));
            a.secret = Base32.clean (secret);
            a.issuer = issuer != null && issuer != "" ? issuer : label_issuer;
            if (a.kind == Kind.HOTP && !have_counter) a.counter = 0;
            if (a.kind == Kind.STEAM) {
                a.digits = 5;
                a.period = 30;
                a.algorithm = Algorithm.SHA1;
                if (a.issuer == "") a.issuer = "Steam";
            } else if (a.digits < 6 || a.digits > 8) {
                throw new AccountError.UNSUPPORTED (_("Codes with %d digits are not supported.").printf (a.digits));
            }
            return a;
        }

        private static bool all_digits (string text) {
            for (int i = 0; i < text.length; i++) if (!text[i].isdigit ()) return false;
            return true;
        }

        private static string escape (string text) {
            return Uri.escape_string (text, null, false);
        }

        public string to_uri () {
            var sb = new StringBuilder ("otpauth://");
            sb.append (kind.to_id ());
            sb.append_c ('/');
            if (issuer != "") {
                sb.append (escape (issuer));
                sb.append_c (':');
            }
            sb.append (escape (name));
            sb.append ("?secret=");
            sb.append (Base32.clean (secret));
            if (issuer != "") sb.append ("&issuer=" + escape (issuer));
            if (kind != Kind.STEAM) {
                sb.append ("&algorithm=" + algorithm.to_id ());
                sb.append ("&digits=%d".printf (digits));
            }
            if (kind == Kind.TOTP) sb.append ("&period=%d".printf (period));
            if (kind == Kind.HOTP) sb.append ("&counter=%s".printf (counter.to_string ()));
            return sb.str;
        }
    }

    public class ImportResult : Object {
        public Gee.ArrayList<Account> accounts = new Gee.ArrayList<Account> ();
        public int skipped;
        public string format = "";
        public string note = "";
    }

    namespace Transfer {
        private Json.Node parse_json (string text) throws AccountError {
            var parser = new Json.Parser ();
            try {
                parser.load_from_data (text);
            } catch (Error e) {
                throw new AccountError.INVALID (_("The file is not valid JSON."));
            }
            var root = parser.get_root ();
            if (root == null) throw new AccountError.INVALID (_("The file is empty."));
            return root;
        }

        private string str (Json.Object o, string name) {
            if (!o.has_member (name)) return "";
            var n = o.get_member (name);
            if (n.get_node_type () != Json.NodeType.VALUE) return "";
            if (n.get_value_type () == typeof (string)) return n.get_string ();
            if (n.get_value_type () == typeof (int64)) return n.get_int ().to_string ();
            return "";
        }

        private int64 num (Json.Object o, string name, int64 fallback) {
            if (!o.has_member (name)) return fallback;
            var n = o.get_member (name);
            if (n.get_node_type () != Json.NodeType.VALUE) return fallback;
            if (n.get_value_type () == typeof (int64)) return n.get_int ();
            if (n.get_value_type () == typeof (string)) {
                int64 v;
                if (int64.try_parse (n.get_string (), out v)) return v;
            }
            return fallback;
        }

        private bool finish (Account a) {
            a.secret = Base32.clean (a.secret);
            if (a.kind == Kind.STEAM) {
                a.digits = 5;
                a.period = 30;
                a.algorithm = Algorithm.SHA1;
            }
            if (a.kind != Kind.STEAM && a.digits == 0) a.digits = 6;
            if (a.period <= 0) a.period = 30;
            return a.validate () == null;
        }

        public ImportResult parse_aegis (string text) throws AccountError {
            var root = parse_json (text);
            if (root.get_node_type () != Json.NodeType.OBJECT) throw new AccountError.INVALID (_("This is not an Aegis backup."));
            var top = root.get_object ();
            if (!top.has_member ("db")) throw new AccountError.INVALID (_("This is not an Aegis backup."));
            var db_node = top.get_member ("db");
            bool slots = false;
            if (top.has_member ("header") && top.get_member ("header").get_node_type () == Json.NodeType.OBJECT) {
                var header = top.get_object_member ("header");
                slots = header.has_member ("slots") && header.get_member ("slots").get_node_type () != Json.NodeType.NULL;
            }
            if (slots || db_node.get_node_type () == Json.NodeType.VALUE) {
                throw new AccountError.ENCRYPTED (_("This Aegis backup is encrypted with a password."));
            }
            if (db_node.get_node_type () != Json.NodeType.OBJECT) throw new AccountError.INVALID (_("This is not an Aegis backup."));
            return parse_aegis_db (db_node.get_object ());
        }

        public ImportResult parse_aegis_encrypted (string text, string password) throws AccountError, VaultError {
            string plain = Vault.open (text, password);
            var root = parse_json (plain);
            if (root.get_node_type () != Json.NodeType.OBJECT) throw new VaultError.INVALID (_("The backup is damaged."));
            return parse_aegis_db (root.get_object ());
        }

        private Gee.HashMap<string, string> aegis_groups (Json.Object db) {
            var groups = new Gee.HashMap<string, string> ();
            if (!db.has_member ("groups") || db.get_member ("groups").get_node_type () != Json.NodeType.ARRAY) return groups;
            foreach (var node in db.get_array_member ("groups").get_elements ()) {
                if (node.get_node_type () != Json.NodeType.OBJECT) continue;
                var g = node.get_object ();
                string uuid = str (g, "uuid"), name = str (g, "name");
                if (uuid != "" && name != "") groups[uuid] = name;
            }
            return groups;
        }

        private string[] entry_tags (Json.Object e, Gee.HashMap<string, string> groups) {
            string[] tags = {};
            if (e.has_member ("groups") && e.get_member ("groups").get_node_type () == Json.NodeType.ARRAY) {
                foreach (var node in e.get_array_member ("groups").get_elements ()) {
                    if (node.get_value_type () != typeof (string)) continue;
                    string? name = groups[node.get_string ()];
                    if (name != null) tags += name;
                }
            }
            string legacy = str (e, "group");
            if (legacy != "") tags += legacy;
            return tags;
        }

        private ImportResult parse_aegis_db (Json.Object db) {
            var result = new ImportResult ();
            result.format = "Aegis";
            if (!db.has_member ("entries") || db.get_member ("entries").get_node_type () != Json.NodeType.ARRAY) return result;
            var groups = aegis_groups (db);
            foreach (var node in db.get_array_member ("entries").get_elements ()) {
                if (node.get_node_type () != Json.NodeType.OBJECT) {
                    result.skipped++;
                    continue;
                }
                var e = node.get_object ();
                var kind = Kind.from_id (str (e, "type"));
                if (kind == null || !e.has_member ("info") || e.get_member ("info").get_node_type () != Json.NodeType.OBJECT) {
                    result.skipped++;
                    continue;
                }
                var info = e.get_object_member ("info");
                var a = new Account ();
                a.kind = kind;
                a.name = str (e, "name");
                a.issuer = str (e, "issuer");
                a.secret = str (info, "secret");
                a.algorithm = Algorithm.from_id (str (info, "algo")) ?? Algorithm.SHA1;
                a.digits = (int) num (info, "digits", 6);
                a.period = (int) num (info, "period", 30);
                a.counter = (uint64) int64.max (0, num (info, "counter", 0));
                a.set_tags (entry_tags (e, groups));
                if (finish (a)) result.accounts.add (a);
                else result.skipped++;
            }
            return result;
        }

        public ImportResult parse_andotp (string text) throws AccountError {
            var root = parse_json (text);
            if (root.get_node_type () != Json.NodeType.ARRAY) throw new AccountError.INVALID (_("This is not an andOTP backup."));
            var result = new ImportResult ();
            result.format = "andOTP";
            foreach (var node in root.get_array ().get_elements ()) {
                if (node.get_node_type () != Json.NodeType.OBJECT) {
                    result.skipped++;
                    continue;
                }
                var e = node.get_object ();
                var kind = Kind.from_id (str (e, "type"));
                if (kind == null) {
                    result.skipped++;
                    continue;
                }
                var a = new Account ();
                a.kind = kind;
                a.secret = str (e, "secret");
                a.issuer = str (e, "issuer");
                string label = str (e, "label");
                if (a.issuer == "" && label.contains (" - ")) {
                    int i = label.index_of (" - ");
                    a.issuer = label.substring (0, i).strip ();
                    label = label.substring (i + 3);
                } else if (a.issuer == "" && label.contains (":")) {
                    int i = label.index_of_char (':');
                    a.issuer = label.substring (0, i).strip ();
                    label = label.substring (i + 1);
                }
                a.name = label.strip ();
                a.algorithm = Algorithm.from_id (str (e, "algorithm")) ?? Algorithm.SHA1;
                a.digits = (int) num (e, "digits", 6);
                a.period = (int) num (e, "period", 30);
                a.counter = (uint64) int64.max (0, num (e, "counter", 0));
                if (finish (a)) result.accounts.add (a);
                else result.skipped++;
            }
            return result;
        }

        public ImportResult parse_uri_list (string text) throws AccountError {
            var result = new ImportResult ();
            result.format = "otpauth";
            bool any = false;
            foreach (string raw in text.split ("\n")) {
                string line = raw.strip ();
                if (line == "" || line.has_prefix ("#")) continue;
                any = true;
                try {
                    if (Migration.is_migration (line)) {
                        var batch = Migration.parse (line);
                        result.accounts.add_all (batch.accounts);
                        result.skipped += batch.skipped;
                    } else {
                        result.accounts.add (Account.parse_uri (line));
                    }
                } catch (AccountError e) {
                    result.skipped++;
                }
            }
            if (!any) throw new AccountError.INVALID (_("The file has no accounts."));
            if (result.accounts.size == 0) throw new AccountError.INVALID (_("No valid otpauth:// links were found in the file."));
            return result;
        }

        public ImportResult parse (string text) throws AccountError {
            string t = text.strip ();
            if (t.has_prefix ("\xef\xbb\xbf")) t = t.substring (3);
            if (t.has_prefix ("{")) return parse_aegis (t);
            if (t.has_prefix ("[")) return parse_andotp (t);
            if (Migration.is_migration (t) && !t.contains ("\n")) return Migration.parse (t);
            return parse_uri_list (t);
        }

        public string export_uri_list (Gee.List<Account> accounts) {
            var sb = new StringBuilder ();
            foreach (var a in accounts) {
                if (a.secret == "") continue;
                sb.append (a.to_uri ());
                sb.append_c ('\n');
            }
            return sb.str;
        }

        private Json.Node aegis_db (Gee.List<Account> accounts) {
            var group_ids = new Gee.HashMap<string, string> ();
            var group_names = new Gee.ArrayList<string> ();
            foreach (var a in accounts) {
                if (a.secret == "") continue;
                foreach (string t in a.tags) {
                    if (group_ids.has_key (t.casefold ())) continue;
                    group_ids[t.casefold ()] = Uuid.string_random ();
                    group_names.add (t);
                }
            }
            var b = new Json.Builder ();
            b.begin_object ();
            b.set_member_name ("version").add_int_value (3);
            b.set_member_name ("entries");
            b.begin_array ();
            foreach (var a in accounts) {
                if (a.secret == "") continue;
                b.begin_object ();
                b.set_member_name ("type").add_string_value (a.kind.to_id ());
                b.set_member_name ("uuid").add_string_value (a.id != "" ? a.id : Uuid.string_random ());
                b.set_member_name ("name").add_string_value (a.name);
                b.set_member_name ("issuer").add_string_value (a.issuer);
                b.set_member_name ("note").add_string_value ("");
                b.set_member_name ("favorite").add_boolean_value (false);
                b.set_member_name ("icon").add_null_value ();
                b.set_member_name ("icon_mime").add_null_value ();
                b.set_member_name ("icon_hash").add_null_value ();
                b.set_member_name ("info");
                b.begin_object ();
                b.set_member_name ("secret").add_string_value (Base32.clean (a.secret));
                b.set_member_name ("algo").add_string_value (a.algorithm.to_id ());
                b.set_member_name ("digits").add_int_value (a.code_digits ());
                if (a.kind == Kind.HOTP) b.set_member_name ("counter").add_int_value ((int64) a.counter);
                else b.set_member_name ("period").add_int_value (a.code_period ());
                b.end_object ();
                b.set_member_name ("groups");
                b.begin_array ();
                foreach (string t in a.tags) b.add_string_value (group_ids[t.casefold ()]);
                b.end_array ();
                b.end_object ();
            }
            b.end_array ();
            b.set_member_name ("groups");
            b.begin_array ();
            foreach (string name in group_names) {
                b.begin_object ();
                b.set_member_name ("uuid").add_string_value (group_ids[name.casefold ()]);
                b.set_member_name ("name").add_string_value (name);
                b.end_object ();
            }
            b.end_array ();
            b.end_object ();
            return b.get_root ();
        }

        private string to_text (Json.Node node, bool pretty) {
            var gen = new Json.Generator ();
            gen.pretty = pretty;
            gen.set_root (node);
            return gen.to_data (null);
        }

        public string export_aegis_encrypted (Gee.List<Account> accounts, string password, uint64 n = Vault.DEFAULT_N) throws VaultError {
            return Vault.seal (to_text (aegis_db (accounts), false), password, n);
        }

        public string export_aegis (Gee.List<Account> accounts) {
            var b = new Json.Builder ();
            b.begin_object ();
            b.set_member_name ("version").add_int_value (1);
            b.set_member_name ("header");
            b.begin_object ();
            b.set_member_name ("slots").add_null_value ();
            b.set_member_name ("params").add_null_value ();
            b.end_object ();
            b.set_member_name ("db").add_value (aegis_db (accounts));
            b.end_object ();
            return to_text (b.get_root (), true);
        }
    }
}
