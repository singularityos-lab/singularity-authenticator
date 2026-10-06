namespace Singularity.Apps.Authenticator {

    public class AuthSearch : Singularity.SearchProviderService {
        public const uint CLEAR_SECONDS = 30;
        private const string LOCKED_ID = "locked";
        private const string[] PREFIXES = { "2fa", "otp" };

        private weak AuthenticatorApp app;

        public AuthSearch (AuthenticatorApp app) {
            this.app = app;
        }

        private static bool wanted (string[] terms, out string[] words) {
            string[] found = {};
            words = found;
            if (terms.length == 0) return false;
            bool prefixed = false;
            foreach (unowned string p in PREFIXES) if (terms[0].down () == p) prefixed = true;
            if (!prefixed) return false;
            for (int i = 1; i < terms.length; i++) found += terms[i].casefold ();
            words = found;
            return true;
        }

        private static bool matches (Account a, string[] words) {
            string hay = (a.issuer + " " + a.name + " " + string.joinv (" ", a.tags)).casefold ();
            foreach (string w in words) if (!hay.contains (w)) return false;
            return true;
        }

        private async bool available () {
            if (app.store.items.size == 0) return false;
            if (app.window_unlocked ()) return true;
            if (app.config.lock_mode != LockMode.NONE) return false;
            return yield Keyring.is_open ();
        }

        public override async string[] get_initial_results (string[] terms, Cancellable? cancellable) throws Error {
            string[] words;
            if (!wanted (terms, out words)) return {};
            if (app.store.items.size == 0) return {};
            if (!(yield available ())) return { LOCKED_ID };
            string[] ids = {};
            foreach (var a in app.store.sorted ()) if (matches (a, words)) ids += a.id;
            return ids;
        }

        public override async Singularity.SearchResultMeta[] get_result_metas (string[] ids, Cancellable? cancellable) throws Error {
            Singularity.SearchResultMeta[] metas = {};
            int64 now = new DateTime.now_utc ().to_unix ();
            foreach (string id in ids) {
                if (id == LOCKED_ID) {
                    var meta = new Singularity.SearchResultMeta (id, _("Authenticator Is Locked"));
                    meta.description = _("Open Authenticator to unlock your codes");
                    metas += meta;
                    continue;
                }
                var a = app.store.find (id);
                if (a == null) continue;
                var meta = new Singularity.SearchResultMeta (id, a.title ());
                string when = a.kind == Kind.HOTP
                    ? _("Counter-based code")
                    : ngettext ("Next code in %d second", "Next code in %d seconds", Otp.seconds_left (now, a.code_period ())).printf (Otp.seconds_left (now, a.code_period ()));
                string sub = a.subtitle ();
                meta.description = sub != "" ? "%s, %s".printf (sub, when) : when;
                string? domain = Provider.domain_for (a.issuer);
                if (domain != null) {
                    string? path = IconCache.cached_path (domain);
                    if (path != null) meta.icon = new FileIcon (File.new_for_path (path));
                }
                metas += meta;
            }
            return metas;
        }

        public override async Singularity.SearchActivationReply? activate_result (string id, string[] terms, uint32 timestamp) throws Error {
            var reply = yield copy_reply (id);
            if (reply == null) app.activate ();
            return reply;
        }

        public async Singularity.SearchActivationReply? copy_reply (string id) {
            var a = app.store.find (id);
            if (id == LOCKED_ID || a == null || !(yield available ())) return null;
            string? secret = null;
            try {
                secret = a.secret != "" ? a.secret : yield Keyring.lookup (a.id);
            } catch (Error e) {
                return null;
            }
            if (secret == null || secret == "") return null;
            var probe = a.copy ();
            probe.secret = secret;
            string? code = probe.code (new DateTime.now_utc ().to_unix ());
            probe.secret = "";
            secret = null;
            if (code == null) return null;
            return Singularity.SearchActivationReply.copy (code, true, CLEAR_SECONDS);
        }

        public override void launch_search (string[] terms, uint32 timestamp) {
            app.activate ();
        }
    }
}
