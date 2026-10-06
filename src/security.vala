namespace Singularity.Apps.Authenticator {

    namespace Pbkdf2 {
        public uint8[] derive (Algorithm algorithm, uint8[] password, uint8[] salt, uint iterations, int length) {
            var result = new uint8[length];
            int hlen = algorithm == Algorithm.SHA512 ? 64 : (algorithm == Algorithm.SHA256 ? 32 : 20);
            int blocks = (length + hlen - 1) / hlen;
            int pos = 0;
            for (int i = 1; i <= blocks; i++) {
                var first = new uint8[salt.length + 4];
                Memory.copy (first, salt, salt.length);
                first[salt.length] = (uint8) ((i >> 24) & 0xff);
                first[salt.length + 1] = (uint8) ((i >> 16) & 0xff);
                first[salt.length + 2] = (uint8) ((i >> 8) & 0xff);
                first[salt.length + 3] = (uint8) (i & 0xff);
                var u = Otp.hmac (algorithm, password, first);
                var t = u;
                for (uint j = 1; j < iterations; j++) {
                    u = Otp.hmac (algorithm, password, u);
                    for (int k = 0; k < hlen; k++) t[k] ^= u[k];
                }
                for (int k = 0; k < hlen && pos < length; k++) result[pos++] = t[k];
            }
            return result;
        }

        public string to_hex (uint8[] data) {
            var sb = new StringBuilder ();
            foreach (uint8 b in data) sb.append_printf ("%02x", b);
            return sb.str;
        }
    }

    namespace PasswordHash {
        public const uint ITERATIONS = 120000;

        public string create (string password, uint iterations = ITERATIONS) {
            var salt = random_bytes (16);
            var key = Pbkdf2.derive (Algorithm.SHA256, password.data, salt, iterations, 32);
            return "pbkdf2-sha256$%u$%s$%s".printf (iterations, Base64.encode (salt), Base64.encode (key));
        }

        public uint8[] random_bytes (int n) {
            var buf = new uint8[n];
            var f = FileStream.open ("/dev/urandom", "rb");
            if (f == null || f.read (buf) != n) {
                for (int i = 0; i < n; i++) buf[i] = (uint8) Random.int_range (0, 256);
            }
            return buf;
        }

        public bool verify (string password, string stored) {
            string[] parts = stored.split ("$");
            if (parts.length != 4 || parts[0] != "pbkdf2-sha256") return false;
            uint64 iterations;
            if (!uint64.try_parse (parts[1], out iterations) || iterations == 0 || iterations > 10000000) return false;
            var salt = Base64.decode (parts[2]);
            var expected = Base64.decode (parts[3]);
            if (expected.length == 0) return false;
            var key = Pbkdf2.derive (Algorithm.SHA256, password.data, salt, (uint) iterations, expected.length);
            uint8 diff = 0;
            for (int i = 0; i < expected.length; i++) diff |= key[i] ^ expected[i];
            return diff == 0;
        }
    }

    public errordomain KeyringError {
        UNAVAILABLE,
        LOCKED,
        FAILED
    }

    namespace Keyring {
        private Secret.Schema account_schema () {
            return new Secret.Schema ("dev.sinty.authenticator", Secret.SchemaFlags.NONE,
                "account", Secret.SchemaAttributeType.STRING);
        }

        private Secret.Schema lock_schema () {
            return new Secret.Schema ("dev.sinty.authenticator.lock", Secret.SchemaFlags.NONE,
                "purpose", Secret.SchemaAttributeType.STRING);
        }

        private Error wrap (Error e) {
            if (e is IOError.CANCELLED) return e;
            if (e is DBusError.SERVICE_UNKNOWN || e is DBusError.NAME_HAS_NO_OWNER || e is DBusError.SPAWN_EXEC_FAILED || e is DBusError.SPAWN_SERVICE_NOT_FOUND) {
                return new KeyringError.UNAVAILABLE (_("The system keyring is not running."));
            }
            if (e.domain == Secret.Error.get_quark () && e.code == Secret.Error.IS_LOCKED) return new KeyringError.LOCKED (_("The keyring is locked."));
            return new KeyringError.FAILED (e.message);
        }

        public async void check () throws Error {
            try {
                yield Secret.Service.get (Secret.ServiceFlags.OPEN_SESSION, null);
            } catch (Error e) {
                throw wrap (e);
            }
        }

        public async string? lookup (string id) throws Error {
            try {
                return yield Secret.password_lookup (account_schema (), null, "account", id);
            } catch (Error e) {
                throw wrap (e);
            }
        }

        public async void store (Account a) throws Error {
            string label = a.subtitle () != "" ? _("Authenticator: %s (%s)").printf (a.title (), a.subtitle ()) : _("Authenticator: %s").printf (a.title ());
            try {
                bool ok = yield Secret.password_store (account_schema (), Secret.COLLECTION_DEFAULT, label, Base32.clean (a.secret), null, "account", a.id);
                if (!ok) throw new KeyringError.FAILED (_("The keyring refused to store the secret."));
            } catch (Error e) {
                throw wrap (e);
            }
        }

        public async void remove (string id) {
            try {
                yield Secret.password_clear (account_schema (), null, "account", id);
            } catch (Error e) {
                warning ("authenticator: %s", e.message);
            }
        }

        public async string? lookup_lock () throws Error {
            if (!(yield unlock_default ())) throw new KeyringError.LOCKED (_("The keyring is locked."));
            try {
                return yield Secret.password_lookup (lock_schema (), null, "purpose", "app-lock");
            } catch (Error e) {
                throw wrap (e);
            }
        }

        public async void store_lock (string? hash) throws Error {
            try {
                if (hash == null) {
                    yield Secret.password_clear (lock_schema (), null, "purpose", "app-lock");
                    return;
                }
                yield Secret.password_store (lock_schema (), Secret.COLLECTION_DEFAULT, _("Authenticator lock password"), hash, null, "purpose", "app-lock");
            } catch (Error e) {
                throw wrap (e);
            }
        }

        private async Secret.Collection? default_collection (Secret.Service service) throws Error {
            return yield Secret.Collection.for_alias (service, "default", Secret.CollectionFlags.NONE, null);
        }

        public async void lock_default () throws Error {
            try {
                var service = yield Secret.Service.get (Secret.ServiceFlags.OPEN_SESSION, null);
                var collection = yield default_collection (service);
                if (collection == null) return;
                var objects = new List<DBusProxy> ();
                objects.append (collection);
                List<DBusProxy> locked;
                yield service.lock (objects, null, out locked);
            } catch (Error e) {
                throw wrap (e);
            }
        }

        public async bool is_open () {
            try {
                var service = yield Secret.Service.get (Secret.ServiceFlags.OPEN_SESSION, null);
                var collection = yield default_collection (service);
                return collection != null && !collection.locked;
            } catch (Error e) {
                return false;
            }
        }

        public async bool unlock_default () throws Error {
            try {
                var service = yield Secret.Service.get (Secret.ServiceFlags.OPEN_SESSION, null);
                var collection = yield default_collection (service);
                if (collection == null) return true;
                if (!collection.locked) return true;
                var objects = new List<DBusProxy> ();
                objects.append (collection);
                List<DBusProxy> unlocked;
                int n = yield service.unlock (objects, null, out unlocked);
                return n > 0 && !collection.locked;
            } catch (Error e) {
                throw wrap (e);
            }
        }
    }
}
