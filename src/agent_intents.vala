namespace Singularity.Apps.Authenticator {

    internal class AuthenticatorIntents : Object {

        private static string text(Json.Object args, string key) {
            return args.has_member(key) ? args.get_string_member(key).strip() : "";
        }

        private static Account find(AuthenticatorApp app, string id) throws Error {
            if (id == "") throw new IOError.INVALID_ARGUMENT("give the account id or name from authenticator_accounts");
            var a = app.store.find(id);
            if (a != null) return a;
            Account? match = null;
            string want = id.casefold();
            foreach (var x in app.store.items) {
                if (x.title().casefold() == want || x.issuer.casefold() == want || x.name.casefold() == want) {
                    if (match != null) throw new IOError.INVALID_ARGUMENT("more than one account matches %s: use its id", id);
                    match = x;
                }
            }
            if (match == null) throw new IOError.NOT_FOUND("no account %s", id);
            return match;
        }

        private static async void copy_code(AuthenticatorApp app, Json.Object args, owned Singularity.AppIntentReply reply) {
            app.hold();
            try {
                var a = find(app, text(args, "id"));
                var r = yield app.search.copy_reply(a.id);
                if (r == null || r.copy_text == null) {
                    throw new IOError.PERMISSION_DENIED("Authenticator is locked or the secret is not available; the person has to unlock it first");
                }
                int left = Otp.seconds_left(new DateTime.now_utc().to_unix(), a.code_period());
                var b = new Json.Builder();
                b.begin_object();
                b.set_member_name("copied").add_string_value("code");
                b.set_member_name("account").add_string_value(a.title());
                if (a.kind != Kind.HOTP) b.set_member_name("valid_for_seconds").add_int_value(left);
                b.set_member_name("clears_in_seconds").add_int_value(AuthSearch.CLEAR_SECONDS);
                b.set_member_name("private").begin_object();
                b.set_member_name("clipboard").begin_object();
                b.set_member_name("text").add_string_value(r.copy_text);
                b.set_member_name("sensitive").add_boolean_value(true);
                b.set_member_name("clear_after").add_int_value(AuthSearch.CLEAR_SECONDS);
                b.end_object();
                b.end_object();
                b.end_object();
                reply(b.get_root(), null);
            } catch (Error e) {
                reply(null, e);
            } finally {
                app.release();
            }
        }

        internal static void install(AuthenticatorApp app) {
            var agent = app.agent;
            agent.add_intent("authenticator_accounts", "The two-factor accounts in Authenticator, by name, with tags and favorites. Codes and secrets are never listed.",
                "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}", Singularity.AppIntentRisk.READ, (args) => {
                    string q = text(args, "query").casefold();
                    var b = new Json.Builder();
                    b.begin_array();
                    foreach (var a in app.store.sorted()) {
                        if (q != "" && !a.title().casefold().contains(q) && !a.subtitle().casefold().contains(q)) continue;
                        b.begin_object();
                        b.set_member_name("id").add_string_value(a.id);
                        b.set_member_name("name").add_string_value(a.title());
                        if (a.subtitle() != "") b.set_member_name("account").add_string_value(a.subtitle());
                        b.set_member_name("kind").add_string_value(a.kind.to_id());
                        if (a.favorite) b.set_member_name("favorite").add_boolean_value(true);
                        if (a.tags.length > 0) {
                            b.set_member_name("tags").begin_array();
                            foreach (string t in a.tags) b.add_string_value(t);
                            b.end_array();
                        }
                        b.end_object();
                    }
                    b.end_array();
                    return b.get_root();
                });
            agent.add_async_intent("authenticator_copy_code", "Copy the current sign-in code of an account to the clipboard for the person to paste; it clears itself after 30 seconds. The code is never returned.",
                "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}},\"required\":[\"id\"]}",
                Singularity.AppIntentRisk.UNDOABLE, (args, reply) => {
                    copy_code.begin(app, args, (owned) reply);
                });
        }
    }
}
