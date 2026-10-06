using Gtk;

namespace Singularity.Apps.Authenticator {

    public class CodeDockMenu : Singularity.DockMenu {
        private weak AuthenticatorApp app;
        private weak AuthSearch search;

        public CodeDockMenu (AuthenticatorApp app, AuthSearch search) {
            Object (app_id: "dev.sinty.authenticator");
            this.app = app;
            this.search = search;
        }

        public override async Singularity.SearchActivationReply? reply_for_item (string item_id) {
            var reply = yield search.copy_reply (item_id);
            if (reply == null) app.reveal_account (item_id);
            return reply;
        }
    }

    public class AuthenticatorApp : Singularity.Application {
        public AccountStore store;
        public Config config;
        public IconCache icons;
        public const int DOCK_FAVORITES = 3;
        private AuthSearch search;
        private Singularity.DockMenu? dock_menu;
        private bool add_pending;

        public AuthenticatorApp () {
            Object (application_id: "dev.sinty.authenticator", flags: ApplicationFlags.HANDLES_OPEN);
            add_main_option ("add-account", 0, OptionFlags.NONE, OptionArg.NONE, _("Add a new account"), null);
            search = new AuthSearch (this);
            search.export (this);
        }

        protected override int handle_local_options (VariantDict options) {
            if (!options.contains ("add-account")) return -1;
            try {
                register (null);
            } catch (Error e) {
                warning ("authenticator: %s", e.message);
                return 1;
            }
            if (get_is_remote ()) {
                activate_action ("add-account", null);
                return 0;
            }
            add_pending = true;
            return -1;
        }

        protected override void startup () {
            base.startup ();
            config = new Config ();
            store = new AccountStore ();
            icons = new IconCache ();
            dock_menu = new CodeDockMenu (this, search);
            store.changed.connect (() => publish_dock ());
            publish_dock ();
            var provider = new CssProvider ();
            provider.load_from_string (CSS);
            StyleContext.add_provider_for_display (Gdk.Display.get_default (), provider, STYLE_PROVIDER_PRIORITY_USER + 1);
            var menu = new GLib.Menu ();
            var file = new GLib.Menu ();
            var f1 = new GLib.Menu ();
            f1.append (_("Add Account"), "win.add");
            f1.append (_("Import…"), "win.import");
            if (Qr.AVAILABLE) f1.append (_("Scan QR Code from an Image…"), "win.import-qr");
            f1.append (_("Export…"), "win.export");
            f1.append (_("Back Up with a Password…"), "win.backup");
            file.append_section (null, f1);
            var f2 = new GLib.Menu ();
            f2.append (_("Change Password…"), "win.change-password");
            f2.append (_("Lock"), "win.lock");
            file.append_section (null, f2);
            var f3 = new GLib.Menu ();
            f3.append (_("Close Window"), "win.close");
            f3.append (_("Quit"), "app.quit");
            file.append_section (null, f3);
            menu.append_submenu (_("File"), file);
            var edit = new GLib.Menu ();
            var e1 = new GLib.Menu ();
            e1.append (_("Find"), "win.find");
            edit.append_section (null, e1);
            var e2 = new GLib.Menu ();
            e2.append (_("Settings"), "app.settings");
            edit.append_section (null, e2);
            menu.append_submenu (_("Edit"), edit);
            var view = new GLib.Menu ();
            var v1 = new GLib.Menu ();
            v1.append (_("All Accounts"), "win.tag-all");
            v1.append (_("Next Tag"), "win.tag-next");
            v1.append (_("Previous Tag"), "win.tag-previous");
            view.append_section (null, v1);
            var v2 = new GLib.Menu ();
            v2.append (_("Reload Provider Icons"), "win.refresh-icons");
            view.append_section (null, v2);
            menu.append_submenu (_("View"), view);
            set_menubar (menu);
            var quit = new SimpleAction ("quit", null);
            quit.activate.connect (() => {
                foreach (var w in get_windows ()) w.close ();
            });
            add_action (quit);
            var settings_action = new SimpleAction ("settings", null);
            settings_action.activate.connect (() => {
                try {
                    Singularity.Shell.ShellService shell = Bus.get_proxy_sync (BusType.SESSION, "dev.sinty.desktop", "/dev/sinty/Shell");
                    shell.open_app_settings ("dev.sinty.authenticator");
                } catch (Error e) {
                    warning ("Failed to open settings: %s", e.message);
                }
            });
            add_action (settings_action);
            var add_account = new SimpleAction ("add-account", null);
            add_account.activate.connect (() => {
                var w = main_window ();
                w.present ();
                w.add_when_ready ();
            });
            add_action (add_account);
            set_accels_for_action ("app.quit", { "<Control>q" });
            set_accels_for_action ("win.add", { "<Control>n" });
            set_accels_for_action ("win.import", { "<Control>o" });
            set_accels_for_action ("win.export", { "<Control>s" });
            set_accels_for_action ("win.backup", { "<Control><Shift>s" });
            set_accels_for_action ("win.tag-all", { "<Control>0" });
            set_accels_for_action ("win.tag-next", { "<Control>Page_Down" });
            set_accels_for_action ("win.tag-previous", { "<Control>Page_Up" });
            set_accels_for_action ("win.find", { "<Control>f" });
            set_accels_for_action ("win.lock", { "<Control>l" });
            set_accels_for_action ("win.close", { "<Control>w" });
            set_accels_for_action ("app.settings", { "<Control>comma" });
        }

        public override void activate () {
            var w = main_window ();
            w.present ();
            if (add_pending) {
                add_pending = false;
                w.add_when_ready ();
            }
        }

        public override void open (File[] files, string hint) {
            var w = main_window ();
            w.present ();
            foreach (var file in files) {
                string uri = file.get_uri ();
                if (!uri.has_prefix ("otpauth://")) continue;
                try {
                    w.add_prefilled_when_ready (Account.parse_uri (uri));
                } catch (AccountError e) {
                    warning ("authenticator: %s", e.message);
                }
                break;
            }
        }

        public void reveal_account (string id) {
            var w = main_window ();
            if (w.get_mapped () && !w.is_active) w.set_visible (false);
            w.present ();
            w.reveal_when_ready (id);
        }

        private AuthenticatorWindow main_window () {
            foreach (var w in get_windows ()) {
                if (w is AuthenticatorWindow) return (AuthenticatorWindow) w;
            }
            return new AuthenticatorWindow (this);
        }

        public bool window_unlocked () {
            foreach (var w in get_windows ()) {
                var aw = w as AuthenticatorWindow;
                if (aw != null && aw.secrets_ready) return true;
            }
            return false;
        }

        private void publish_dock () {
            if (dock_menu == null) return;
            dock_menu.clear ();
            int shown = 0;
            foreach (var a in store.sorted ()) {
                if (!a.favorite || shown >= DOCK_FAVORITES) continue;
                string sub = a.subtitle ();
                string name = sub != "" ? "%s (%s)".printf (a.title (), sub) : a.title ();
                dock_menu.add_reply_item (a.id, _("Code for %s").printf (name), "edit-copy-symbolic");
                shown++;
            }
            if (shown > 0) dock_menu.publish ();
            else dock_menu.unpublish ();
        }

        private const string CSS = """
.auth-list {
    background: transparent;
}

.auth-list > row {
    border-radius: 16px;
    margin-bottom: 8px;
    background-color: alpha(@window_fg_color, 0.04);
    border: 1px solid alpha(@window_fg_color, 0.06);
    transition: background-color 150ms ease;
}

.auth-list > row:hover {
    background-color: alpha(@window_fg_color, 0.08);
}

.auth-list > row:focus-visible {
    outline: 2px solid alpha(@accent_bg_color, 0.7);
    outline-offset: -2px;
}

.auth-code {
    font-family: monospace;
    font-size: 24px;
    font-weight: 700;
    letter-spacing: 1px;
    color: @accent_color;
}

.auth-code.error {
    font-family: inherit;
    font-size: 13px;
    font-weight: 400;
    letter-spacing: 0;
    color: @error_color;
}

.auth-ring {
    color: @accent_color;
    font-size: 11px;
}
""";
    }

    public static int main (string[] args) {
        Intl.setlocale (LocaleCategory.ALL, "");
        string locale_dir = "/usr/share/locale";
        try {
            string exe = FileUtils.read_link ("/proc/self/exe");
            locale_dir = Path.build_filename (Path.get_dirname (Path.get_dirname (exe)), "share", "locale");
        } catch (Error e) {
        }
        Intl.bindtextdomain ("singularity-authenticator", locale_dir);
        Intl.bind_textdomain_codeset ("singularity-authenticator", "UTF-8");
        Intl.textdomain ("singularity-authenticator");
        return new AuthenticatorApp ().run (args);
    }
}
