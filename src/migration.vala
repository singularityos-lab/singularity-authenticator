namespace Singularity.Apps.Authenticator {

    public errordomain ProtoError {
        TRUNCATED,
        MALFORMED
    }

    public enum WireType {
        VARINT = 0,
        FIXED64 = 1,
        BYTES = 2,
        FIXED32 = 5
    }

    public class ProtoReader : Object {
        private uint8[] data;
        private int pos;
        private int end;

        public ProtoReader (uint8[] data, int start = 0, int end = -1) {
            this.data = data;
            this.pos = start;
            this.end = end < 0 ? data.length : end;
        }

        public bool at_end () {
            return pos >= end;
        }

        public uint64 varint () throws ProtoError {
            uint64 value = 0;
            for (int shift = 0; shift < 64; shift += 7) {
                if (pos >= end) throw new ProtoError.TRUNCATED ("varint runs past the end");
                uint8 b = data[pos++];
                if (shift == 63 && (b & 0x7e) != 0) throw new ProtoError.MALFORMED ("varint overflows 64 bits");
                value |= ((uint64) (b & 0x7f)) << shift;
                if ((b & 0x80) == 0) return value;
            }
            throw new ProtoError.MALFORMED ("varint is longer than 10 bytes");
        }

        public bool next (out uint field, out WireType wire) throws ProtoError {
            field = 0;
            wire = WireType.VARINT;
            if (at_end ()) return false;
            uint64 key = varint ();
            field = (uint) (key >> 3);
            uint type = (uint) (key & 7);
            if (field == 0 || key >> 3 > 0x1fffffff) throw new ProtoError.MALFORMED ("invalid field number");
            if (type != 0 && type != 1 && type != 2 && type != 5) throw new ProtoError.MALFORMED ("unsupported wire type %u".printf (type));
            wire = (WireType) type;
            return true;
        }

        public uint8[] bytes () throws ProtoError {
            uint64 length = varint ();
            if (length > (uint64) (end - pos)) throw new ProtoError.TRUNCATED ("field runs past the end");
            var out_bytes = data[pos:pos + (int) length];
            pos += (int) length;
            return out_bytes;
        }

        public ProtoReader message () throws ProtoError {
            uint64 length = varint ();
            if (length > (uint64) (end - pos)) throw new ProtoError.TRUNCATED ("message runs past the end");
            var sub = new ProtoReader (data, pos, pos + (int) length);
            pos += (int) length;
            return sub;
        }

        public string text () throws ProtoError {
            var raw = bytes ();
            var buf = new uint8[raw.length + 1];
            Memory.copy (buf, raw, raw.length);
            string s = ((string) buf).dup ();
            if (s.length != raw.length || !s.validate ()) throw new ProtoError.MALFORMED ("text is not UTF-8");
            return s;
        }

        public void skip (WireType wire) throws ProtoError {
            switch (wire) {
                case WireType.VARINT:
                    varint ();
                    break;
                case WireType.FIXED64:
                    advance (8);
                    break;
                case WireType.FIXED32:
                    advance (4);
                    break;
                case WireType.BYTES:
                    bytes ();
                    break;
            }
        }

        private void advance (int n) throws ProtoError {
            if (end - pos < n) throw new ProtoError.TRUNCATED ("fixed field runs past the end");
            pos += n;
        }
    }

    public class MigrationResult : ImportResult {
        public int batch_index;
        public int batch_size = 1;
        public int batch_id;
    }

    namespace Migration {
        public const string SCHEME = "otpauth-migration";

        public bool is_migration (string text) {
            return text.strip ().down ().has_prefix (SCHEME + "://");
        }

        public uint8[] payload_from_uri (string text) throws AccountError {
            string uri = text.strip ();
            if (!is_migration (uri)) throw new AccountError.INVALID (_("This is not a Google Authenticator export."));
            int q = uri.index_of_char ('?');
            string? data = null;
            if (q >= 0) {
                string query = uri.substring (q + 1);
                int hash = query.index_of_char ('#');
                if (hash >= 0) query = query.substring (0, hash);
                foreach (string pair in query.split ("&")) {
                    int eq = pair.index_of_char ('=');
                    if (eq < 0 || pair.substring (0, eq).down () != "data") continue;
                    data = Uri.unescape_string (pair.substring (eq + 1)) ?? pair.substring (eq + 1);
                }
            }
            if (data == null || data.strip () == "") throw new AccountError.INVALID (_("The Google Authenticator export has no accounts in it."));
            string b64 = data.strip ().replace (" ", "+").replace ("-", "+").replace ("_", "/");
            for (int i = 0; i < b64.length; i++) {
                char c = b64[i];
                if (!(c.isalnum () || c == '+' || c == '/' || c == '=')) throw new AccountError.INVALID (_("The Google Authenticator export is damaged."));
            }
            while (b64.length % 4 != 0) b64 += "=";
            var raw = Base64.decode (b64);
            if (raw.length == 0) throw new AccountError.INVALID (_("The Google Authenticator export is damaged."));
            return raw;
        }

        private Account? read_account (ProtoReader r) throws ProtoError {
            var a = new Account ();
            uint8[]? secret = null;
            int algorithm = 1, digits = 1, type = 2;
            uint field;
            WireType wire;
            while (r.next (out field, out wire)) {
                if (field == 1 && wire == WireType.BYTES) secret = r.bytes ();
                else if (field == 2 && wire == WireType.BYTES) a.name = r.text ();
                else if (field == 3 && wire == WireType.BYTES) a.issuer = r.text ();
                else if (field == 4 && wire == WireType.VARINT) algorithm = (int) r.varint ();
                else if (field == 5 && wire == WireType.VARINT) digits = (int) r.varint ();
                else if (field == 6 && wire == WireType.VARINT) type = (int) r.varint ();
                else if (field == 7 && wire == WireType.VARINT) a.counter = r.varint ();
                else r.skip (wire);
            }
            if (secret == null || secret.length == 0) return null;
            a.secret = Base32.encode (secret);
            switch (algorithm) {
                case 0:
                case 1: a.algorithm = Algorithm.SHA1; break;
                case 2: a.algorithm = Algorithm.SHA256; break;
                case 3: a.algorithm = Algorithm.SHA512; break;
                default: return null;
            }
            switch (digits) {
                case 0:
                case 1: a.digits = 6; break;
                case 2: a.digits = 8; break;
                default: return null;
            }
            switch (type) {
                case 1: a.kind = Kind.HOTP; break;
                case 0:
                case 2: a.kind = Kind.TOTP; break;
                default: return null;
            }
            a.period = 30;
            split_label (a);
            return a.validate () == null ? a : null;
        }

        private void split_label (Account a) {
            string name = a.name.strip ();
            int colon = name.index_of_char (':');
            if (colon > 0) {
                string prefix = name.substring (0, colon).strip ();
                if (a.issuer == "" || a.issuer.down () == prefix.down ()) {
                    if (a.issuer == "") a.issuer = prefix;
                    name = name.substring (colon + 1).strip ();
                }
            }
            a.name = name;
            a.issuer = a.issuer.strip ();
        }

        public MigrationResult decode (uint8[] payload) throws AccountError {
            var result = new MigrationResult ();
            result.format = "Google Authenticator";
            try {
                var r = new ProtoReader (payload);
                uint field;
                WireType wire;
                while (r.next (out field, out wire)) {
                    if (field == 1 && wire == WireType.BYTES) {
                        var a = read_account (r.message ());
                        if (a != null) result.accounts.add (a);
                        else result.skipped++;
                    } else if (field == 3 && wire == WireType.VARINT) {
                        result.batch_size = (int) uint64.min (r.varint (), 1000);
                    } else if (field == 4 && wire == WireType.VARINT) {
                        result.batch_index = (int) uint64.min (r.varint (), 1000);
                    } else if (field == 5 && wire == WireType.VARINT) {
                        result.batch_id = (int) (r.varint () & 0x7fffffff);
                    } else {
                        r.skip (wire);
                    }
                }
            } catch (ProtoError e) {
                throw new AccountError.INVALID (_("The Google Authenticator export is damaged."));
            }
            if (result.batch_size < 1) result.batch_size = 1;
            if (result.accounts.size == 0 && result.skipped == 0) throw new AccountError.INVALID (_("The Google Authenticator export has no accounts in it."));
            return result;
        }

        public MigrationResult parse (string uri) throws AccountError {
            return decode (payload_from_uri (uri));
        }
    }
}
