namespace Singularity.Apps.Authenticator {

    public enum Kind {
        TOTP,
        HOTP,
        STEAM;

        public string to_id () {
            switch (this) {
                case HOTP: return "hotp";
                case STEAM: return "steam";
                default: return "totp";
            }
        }

        public static Kind? from_id (string id) {
            switch (id.down ()) {
                case "totp": return TOTP;
                case "hotp": return HOTP;
                case "steam": return STEAM;
                default: return null;
            }
        }
    }

    public enum Algorithm {
        SHA1,
        SHA256,
        SHA512;

        public string to_id () {
            switch (this) {
                case SHA256: return "SHA256";
                case SHA512: return "SHA512";
                default: return "SHA1";
            }
        }

        public static Algorithm? from_id (string id) {
            string s = id.up ().replace ("-", "").replace ("HMAC", "");
            switch (s) {
                case "SHA1": return SHA1;
                case "SHA256": return SHA256;
                case "SHA512": return SHA512;
                default: return null;
            }
        }

        public ChecksumType checksum () {
            switch (this) {
                case SHA256: return ChecksumType.SHA256;
                case SHA512: return ChecksumType.SHA512;
                default: return ChecksumType.SHA1;
            }
        }
    }

    namespace Base32 {
        private const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public string clean (string text) {
            var sb = new StringBuilder ();
            for (int i = 0; i < text.length; i++) {
                char c = text[i];
                if (c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r') continue;
                sb.append_c (c.toupper ());
            }
            string s = sb.str;
            while (s.has_suffix ("=")) s = s.substring (0, s.length - 1);
            return s;
        }

        public uint8[]? decode (string text) {
            string s = clean (text);
            if (s == "") return null;
            var out_bytes = new ByteArray ();
            uint64 buffer = 0;
            int bits = 0;
            for (int i = 0; i < s.length; i++) {
                int v = ALPHABET.index_of_char (s[i]);
                if (v < 0) return null;
                buffer = (buffer << 5) | (uint64) v;
                bits += 5;
                if (bits >= 8) {
                    bits -= 8;
                    out_bytes.append ({ (uint8) ((buffer >> bits) & 0xff) });
                }
            }
            if (out_bytes.len == 0) return null;
            uint8[] result = out_bytes.data;
            return result;
        }

        public string encode (uint8[] data, bool padding = false) {
            var sb = new StringBuilder ();
            uint64 buffer = 0;
            int bits = 0;
            foreach (uint8 b in data) {
                buffer = (buffer << 8) | b;
                bits += 8;
                while (bits >= 5) {
                    bits -= 5;
                    sb.append_c (ALPHABET[(int) ((buffer >> bits) & 31)]);
                }
            }
            if (bits > 0) sb.append_c (ALPHABET[(int) ((buffer << (5 - bits)) & 31)]);
            if (padding) while (sb.len % 8 != 0) sb.append_c ('=');
            return sb.str;
        }

        public bool is_valid (string text) {
            var d = decode (text);
            return d != null && d.length > 0;
        }
    }

    namespace Otp {
        public const string STEAM_ALPHABET = "23456789BCDFGHJKMNPQRTVWXY";

        public uint8[] hmac (Algorithm algorithm, uint8[] key, uint8[] message) {
            var h = new Hmac (algorithm.checksum (), key);
            h.update (message);
            size_t len = algorithm == Algorithm.SHA512 ? 64 : (algorithm == Algorithm.SHA256 ? 32 : 20);
            var digest = new uint8[len];
            h.get_digest (digest, ref len);
            digest.length = (int) len;
            return digest;
        }

        public uint32 truncate (uint8[] key, uint64 counter, Algorithm algorithm) {
            var msg = new uint8[8];
            for (int i = 7; i >= 0; i--) {
                msg[i] = (uint8) (counter & 0xff);
                counter >>= 8;
            }
            var digest = hmac (algorithm, key, msg);
            int offset = digest[digest.length - 1] & 0x0f;
            return ((uint32) (digest[offset] & 0x7f) << 24)
                | ((uint32) digest[offset + 1] << 16)
                | ((uint32) digest[offset + 2] << 8)
                | (uint32) digest[offset + 3];
        }

        public string hotp (uint8[] key, uint64 counter, int digits = 6, Algorithm algorithm = Algorithm.SHA1) {
            uint32 value = truncate (key, counter, algorithm);
            uint64 mod = 1;
            for (int i = 0; i < digits; i++) mod *= 10;
            string code = ((uint64) value % mod).to_string ();
            while (code.length < digits) code = "0" + code;
            return code;
        }

        public uint64 time_counter (int64 unix_time, int period, int64 t0 = 0) {
            if (period <= 0) period = 30;
            if (unix_time < t0) return 0;
            return (uint64) ((unix_time - t0) / period);
        }

        public string totp (uint8[] key, int64 unix_time, int period = 30, int digits = 6, Algorithm algorithm = Algorithm.SHA1) {
            return hotp (key, time_counter (unix_time, period), digits, algorithm);
        }

        public string steam (uint8[] key, int64 unix_time) {
            uint32 value = truncate (key, time_counter (unix_time, 30), Algorithm.SHA1);
            var sb = new StringBuilder ();
            for (int i = 0; i < 5; i++) {
                sb.append_c (STEAM_ALPHABET[(int) (value % STEAM_ALPHABET.length)]);
                value /= STEAM_ALPHABET.length;
            }
            return sb.str;
        }

        public int seconds_left (int64 unix_time, int period) {
            if (period <= 0) period = 30;
            return period - (int) (unix_time % period);
        }
    }
}
