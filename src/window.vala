using Gtk;
using Singularity.Widgets;

namespace Singularity.Apps.Authenticator {

    public class AccountRow : ListBoxRow {
        public Account account;
        private ProviderAvatar avatar;
        private Label code_label;
        private CircularProgress? ring;
        private Button? next_button;
        private uint64 shown_step = uint64.MAX;
        private uint64 shown_counter = uint64.MAX;
        public signal void next_requested ();

        public AccountRow (Account a, Gdk.Texture? icon) {
            account = a;
            add_css_class ("auth-row");
            var box = new Box (Orientation.HORIZONTAL, 14);
            box.margin_top = 10;
            box.margin_bottom = 10;
            box.margin_start = 14;
            box.margin_end = 14;

            avatar = new ProviderAvatar (40);
            avatar.set_account (a.title (), icon);
            avatar.valign = Align.CENTER;
            box.append (avatar);

            var texts = new Box (Orientation.VERTICAL, 2);
            texts.valign = Align.CENTER;
            texts.hexpand = true;
            var title = new Label (a.title ());
            title.add_css_class ("heading");
            title.xalign = 0;
            title.ellipsize = Pango.EllipsizeMode.END;
            texts.append (title);
            string sub = a.subtitle ();
            if (sub != "") {
                var subtitle = new Label (sub);
                subtitle.add_css_class ("dim-label");
                subtitle.add_css_class ("caption");
                subtitle.xalign = 0;
                subtitle.ellipsize = Pango.EllipsizeMode.END;
                texts.append (subtitle);
            }
            code_label = new Label ("");
            code_label.add_css_class ("auth-code");
            code_label.xalign = 0;
            texts.append (code_label);
            box.append (texts);

            if (a.kind == Kind.HOTP) {
                next_button = new Button.from_icon_name ("view-refresh-symbolic");
                next_button.add_css_class ("flat");
                next_button.add_css_class ("circular");
                next_button.valign = Align.CENTER;
                next_button.tooltip_text = _("Next Code");
                next_button.clicked.connect (() => next_requested ());
                box.append (next_button);
            } else {
                ring = new CircularProgress (30);
                ring.valign = Align.CENTER;
                ring.add_css_class ("auth-ring");
                box.append (ring);
            }
            child = box;
            update_property (Gtk.AccessibleProperty.LABEL, sub != "" ? "%s, %s".printf (a.title (), sub) : a.title (), -1);
        }

        public void set_icon (Gdk.Texture? icon) {
            avatar.set_account (account.title (), icon);
        }

        public string? current_code () {
            if (account.secret == "" || account.secret_missing) return null;
            return account.code (new DateTime.now_utc ().to_unix ());
        }

        public void tick (int64 now) {
            if (account.secret_missing || account.secret == "") {
                code_label.label = _("Secret missing from the keyring");
                code_label.add_css_class ("error");
                if (ring != null) ring.visible = false;
                if (next_button != null) next_button.sensitive = false;
                return;
            }
            int period = account.code_period ();
            if (account.kind == Kind.HOTP) {
                if (shown_counter != account.counter) {
                    shown_counter = account.counter;
                    code_label.label = Account.group_code (account.code (now) ?? "");
                }
                return;
            }
            uint64 step = Otp.time_counter (now, period);
            if (step != shown_step) {
                shown_step = step;
                code_label.label = Account.group_code (account.code (now) ?? "");
            }
            int left = Otp.seconds_left (now, period);
            ring.fraction = (double) left / period;
            ring.label = left.to_string ();
            if (left <= 5) {
                ring.add_css_class ("auth-ring-low");
                ring.color = "#e5484d";
            } else {
                ring.remove_css_class ("auth-ring-low");
                ring.color = null;
            }
        }
    }

    public class AuthenticatorWindow : Singularity.Widgets.Window {
        private AuthenticatorApp app;
        private AccountStore store;
        private Config config;
        private IconCache icons;
        private Stack stack;
        private ListBox list;
        private StatusPage error_page;
        private StatusPage no_results;
        private Stack list_stack;
        private Button add_bubble;
        private Button lock_bubble;
        private SearchBubble search_bubble;
        private PasswordRow unlock_entry;
        private Box unlock_password_box;
        private Button unlock_button;
        private Label unlock_error;
        private Label unlock_title;
        private Overlay overlay_root;
        private Singularity.Widgets.Toast? last_toast = null;
        private uint tick_id;
        private uint idle_lock_id;
        private string filter = "";
        private string? tag_filter;
        private ChipBar tag_bar;
        private string[] shown_tags = {};
        private Gee.ArrayList<Gtk.Window> secret_windows = new Gee.ArrayList<Gtk.Window> ();
        private bool locked;
        private bool loaded;
        private LockMode applied_mode;
        private bool password_pending;
        private bool prompting;
        private ulong settings_handler;
        private Gee.ArrayList<AccountRow> rows = new Gee.ArrayList<AccountRow> ();
        private string? pending_account;
        private bool pending_add;

        public bool secrets_ready {
            get { return loaded && !locked; }
        }

        public AuthenticatorWindow (AuthenticatorApp app) {
            Object (application: app);
            this.app = app;
            store = app.store;
            config = app.config;
            icons = app.icons;
            set_title (_("Authenticator"));
            set_default_size (560, 720);
            set_size_request (360, 420);

            stack = new Stack ();
            stack.transition_type = StackTransitionType.CROSSFADE;
            stack.add_named (build_loading (), "loading");
            stack.add_named (build_welcome (), "welcome");
            stack.add_named (build_list (), "list");
            stack.add_named (build_locked (), "locked");
            stack.add_named (build_error (), "error");
            overlay_root = new Overlay ();
            overlay_root.child = stack;
            set_content (overlay_root);

            add_bubble = add_bubble_icon ("list-add-symbolic", _("Add Account"), () => edit_account (null));
            search_bubble = add_bubble_search (_("Search Accounts"), (t) => {
                filter = t.strip ().down ();
                list.invalidate_filter ();
                sync_empty_search ();
            });
            lock_bubble = add_bubble_icon ("changes-prevent-symbolic", _("Lock"), () => lock_now ());

            install_actions ();
            store.changed.connect (() => {
                if (!locked) rebuild ();
            });
            icons.updated.connect ((domain) => {
                foreach (var r in rows) {
                    if (Provider.domain_for (r.account.issuer) == domain) r.set_icon (icons.get_icon (domain, false));
                }
            });
            applied_mode = config.lock_mode;
            settings_handler = config.settings.changed.connect (on_setting_changed);
            notify["is-active"].connect (() => {
                if (is_active && password_pending) {
                    password_pending = false;
                    apply_lock_mode ();
                }
                schedule_idle_lock ();
                if (is_active && pending_account != null) Timeout.add (250, () => {
                    reveal_pending ();
                    return Source.REMOVE;
                });
            });
            close_request.connect (() => {
                if (settings_handler != 0) config.settings.disconnect (settings_handler);
                settings_handler = 0;
                if (tick_id != 0) Source.remove (tick_id);
                if (idle_lock_id != 0) Source.remove (idle_lock_id);
                tick_id = idle_lock_id = 0;
                return false;
            });
            tick_id = Timeout.add (500, () => {
                tick ();
                return Source.CONTINUE;
            });
            show_page ("loading");
            start.begin ();
        }

        private Widget build_loading () {
            var box = new Box (Orientation.VERTICAL, 12);
            box.valign = Align.CENTER;
            box.halign = Align.CENTER;
            var spinner = new Spinner ();
            spinner.spinning = true;
            spinner.set_size_request (32, 32);
            box.append (spinner);
            var label = new Label (_("Opening the keyring…"));
            label.add_css_class ("dim-label");
            box.append (label);
            return box;
        }

        private Widget build_welcome () {
            var wp = new WelcomePage ();
            wp.app_icon_name = "dev.sinty.authenticator";
            wp.title = _("Authenticator");
            wp.subtitle = _("Sign-in codes for your accounts, kept safe in the system keyring.");
            wp.add_action ("avatar-default", _("Add Account"), _("Enter a secret key or paste a setup link"), () => edit_account (null));
            wp.add_action ("folder-download", _("Import"), _("Aegis backups, also encrypted ones, andOTP, Google Authenticator or a list of links"), () => import_file ());
            if (Qr.AVAILABLE) wp.add_action ("image-x-generic", _("Scan a QR Code"), _("Read a QR code from a screenshot or picture"), () => import_qr ());
            return wp;
        }

        private Widget build_list () {
            list = new ListBox ();
            list.selection_mode = SelectionMode.NONE;
            list.add_css_class ("auth-list");
            list.activate_on_single_click = true;
            list.set_filter_func ((row) => matches (((AccountRow) row).account));
            list.row_activated.connect ((row) => copy_code ((AccountRow) row));
            var holder = new Box (Orientation.VERTICAL, 0);
            holder.margin_top = 64;
            holder.margin_bottom = 24;
            holder.margin_start = 16;
            holder.margin_end = 16;
            tag_bar = new ChipBar ();
            tag_bar.ellipsize_labels = false;
            tag_bar.bar_style = ChipBarStyle.FILTER;
            tag_bar.margin_bottom = 8;
            tag_bar.visible = false;
            tag_bar.chip_activated.connect ((id) => set_tag_filter (id == "" ? null : id));
            tag_bar.chip_context_requested.connect ((id) => tag_menu (id));
            holder.append (tag_bar);
            holder.append (list);
            var scroll = new ScrolledWindow ();
            scroll.hscrollbar_policy = PolicyType.NEVER;
            scroll.child = new Clamp (holder) { maximum = 640 };
            apply_view_edge (scroll);

            no_results = new StatusPage ();
            no_results.icon_name = "system-search";
            no_results.title = _("No Accounts Found");
            no_results.description = _("Try a different provider, account name or tag.");
            var clear = new Button.with_label (_("Clear Search"));
            clear.add_css_class ("pill");
            clear.add_css_class ("suggested-action");
            clear.halign = Align.CENTER;
            clear.clicked.connect (() => search_bubble.clear ());
            no_results.child = clear;

            list_stack = new Stack ();
            list_stack.add_named (scroll, "list");
            list_stack.add_named (no_results, "none");
            return list_stack;
        }

        private Widget build_locked () {
            var box = new Box (Orientation.VERTICAL, 14);
            box.valign = Align.CENTER;
            box.halign = Align.CENTER;
            box.margin_start = 24;
            box.margin_end = 24;
            var icon = new Image.from_icon_name ("dev.sinty.authenticator");
            icon.pixel_size = 96;
            box.append (icon);
            unlock_title = new Label (_("Authenticator Is Locked"));
            unlock_title.add_css_class ("title-1");
            unlock_title.wrap = true;
            unlock_title.justify = Justification.CENTER;
            box.append (unlock_title);
            unlock_password_box = new Box (Orientation.VERTICAL, 8);
            var group = new PreferencesGroup ();
            group.width_request = 320;
            unlock_entry = new PasswordRow (_("Password"));
            unlock_entry.entry_activated.connect (() => try_unlock ());
            unlock_entry.entry_changed.connect (() => unlock_error.visible = false);
            group.add_row (unlock_entry);
            unlock_password_box.append (group);
            box.append (unlock_password_box);
            unlock_error = new Label (_("The password is not correct"));
            unlock_error.add_css_class ("error");
            unlock_error.visible = false;
            box.append (unlock_error);
            unlock_button = new Button.with_label (_("Unlock"));
            unlock_button.add_css_class ("pill");
            unlock_button.add_css_class ("suggested-action");
            unlock_button.halign = Align.CENTER;
            unlock_button.width_request = 160;
            unlock_button.clicked.connect (() => try_unlock ());
            box.append (unlock_button);
            return box;
        }

        private Widget build_error () {
            error_page = new StatusPage ();
            error_page.icon_name = "dialog-error";
            error_page.title = _("The Keyring Is Not Available");
            var retry = new Button.with_label (_("Try Again"));
            retry.add_css_class ("pill");
            retry.add_css_class ("suggested-action");
            retry.halign = Align.CENTER;
            retry.clicked.connect (() => {
                show_page ("loading");
                start.begin ();
            });
            error_page.child = retry;
            return error_page;
        }

        private void install_actions () {
            var entries = new ActionEntry[] {
                { "add", () => { if (!locked && loaded) edit_account (null); } },
                { "import", () => { if (!locked && loaded) import_file (); } },
                { "import-qr", () => { if (!locked && loaded) import_qr (); } },
                { "export", () => { if (!locked && loaded) export_accounts (); } },
                { "backup", () => { if (!locked && loaded) start_backup (); } },
                { "tag-all", () => { if (!locked && loaded) set_tag_filter (null); } },
                { "tag-next", () => { if (!locked && loaded) step_tag (1); } },
                { "tag-previous", () => { if (!locked && loaded) step_tag (-1); } },
                { "change-password", () => { if (!locked && loaded && applied_mode == LockMode.PASSWORD) ask_new_password (this, () => show_toast (_("Password changed")), () => {}); } },
                { "lock", () => lock_now () },
                { "close", () => close () },
                { "find", () => { if (!locked && store.items.size > 0) search_bubble.grab_focus_entry (); } },
                { "refresh-icons", () => {
                    icons.clear ();
                    rebuild ();
                } }
            };
            add_action_entries (entries, this);
            var qr = lookup_action ("import-qr") as SimpleAction;
            if (qr != null) qr.set_enabled (Qr.AVAILABLE);
            sync_lock_actions ();
        }

        private void sync_lock_actions () {
            var change = lookup_action ("change-password") as SimpleAction;
            if (change != null) change.set_enabled (applied_mode == LockMode.PASSWORD && !locked && loaded);
            var lock_action = lookup_action ("lock") as SimpleAction;
            if (lock_action != null) lock_action.set_enabled (applied_mode != LockMode.NONE && !locked && loaded);
            bool usable = !locked && loaded;
            foreach (string name in new string[] { "add", "import", "export", "backup", "refresh-icons" }) {
                var action = lookup_action (name) as SimpleAction;
                if (action != null) action.set_enabled (usable);
            }
            foreach (string name in new string[] { "tag-all", "tag-next", "tag-previous" }) {
                var action = lookup_action (name) as SimpleAction;
                if (action != null) action.set_enabled (usable && shown_tags.length > 0);
            }
            var find_action = lookup_action ("find") as SimpleAction;
            if (find_action != null) find_action.set_enabled (usable && stack.visible_child_name == "list");
            var qr_action = lookup_action ("import-qr") as SimpleAction;
            if (qr_action != null) qr_action.set_enabled (usable && Qr.AVAILABLE);
        }

        private void on_setting_changed (string key) {
            switch (key) {
                case "lock-mode":
                    if (!locked && loaded) apply_lock_mode ();
                    break;
                case "lock-minutes":
                    schedule_idle_lock ();
                    break;
                case "download-icons":
                    if (!config.favicons) icons.clear ();
                    if (!locked && loaded) rebuild ();
                    break;
            }
        }

        private void apply_lock_mode () {
            if (prompting) return;
            LockMode wanted = config.lock_mode;
            if (wanted == applied_mode) {
                sync_lock_state ();
                return;
            }
            if (wanted == LockMode.PASSWORD) {
                if (!get_mapped ()) {
                    password_pending = true;
                    return;
                }
                prompting = true;
                ask_new_password (this, () => {
                    prompting = false;
                    applied_mode = LockMode.PASSWORD;
                    show_toast (_("Password set"));
                    apply_lock_mode ();
                }, () => {
                    prompting = false;
                    if (config.lock_mode == LockMode.PASSWORD) config.lock_mode = applied_mode;
                    else apply_lock_mode ();
                    sync_lock_state ();
                });
                return;
            }
            if (applied_mode == LockMode.PASSWORD) Keyring.store_lock.begin (null);
            applied_mode = wanted;
            sync_lock_state ();
        }

        private void sync_lock_state () {
            lock_bubble.visible = applied_mode != LockMode.NONE && !locked && loaded && (stack.visible_child_name == "list" || stack.visible_child_name == "welcome");
            sync_lock_actions ();
            schedule_idle_lock ();
        }

        private void show_page (string name) {
            stack.visible_child_name = name;
            bool list_page = name == "list";
            bool usable = name == "list" || name == "welcome";
            add_bubble.visible = usable;
            search_bubble.visible = list_page;
            lock_bubble.visible = usable && applied_mode != LockMode.NONE;
            sync_lock_actions ();
            if (name != "list" && filter != "") search_bubble.clear ();
        }

        private async void start () {
            try {
                yield Keyring.check ();
            } catch (Error e) {
                show_keyring_error (e);
                return;
            }
            applied_mode = config.lock_mode;
            if (applied_mode == LockMode.PASSWORD) {
                string? stored = null;
                try {
                    stored = yield Keyring.lookup_lock ();
                } catch (Error e) {
                    show_keyring_error (e);
                    return;
                }
                if (stored == null) applied_mode = LockMode.NONE;
            }
            if (applied_mode != LockMode.NONE) {
                enter_locked ();
                return;
            }
            yield load_secrets ();
        }

        private void show_keyring_error (Error e) {
            locked = false;
            loaded = false;
            bool is_locked = e is KeyringError.LOCKED;
            error_page.title = is_locked ? _("The Keyring Is Locked") : _("The Keyring Is Not Available");
            error_page.description = is_locked
                ? _("Unlock the keyring to see your codes. Your accounts are only kept there.")
                : _("Authenticator keeps secret keys only in the system keyring. Start the keyring service and try again.\n\n%s").printf (e.message);
            show_page ("error");
        }

        private async void load_secrets () {
            try {
                yield store.unlock_secrets ();
            } catch (Error e) {
                show_keyring_error (e);
                return;
            }
            locked = false;
            loaded = true;
            rebuild ();
            reveal_pending ();
            if (applied_mode != LockMode.PASSWORD && config.lock_mode != LockMode.PASSWORD) Keyring.store_lock.begin (null);
            apply_lock_mode ();
            sync_lock_state ();
        }

        private void rebuild () {
            Widget? child;
            while ((child = list.get_first_child ()) != null) list.remove (child);
            rows.clear ();
            foreach (var a in store.sorted ()) {
                string? domain = Provider.domain_for (a.issuer);
                Gdk.Texture? tex = domain != null ? icons.get_icon (domain, config.favicons) : null;
                var row = new AccountRow (a, tex);
                row.next_requested.connect (() => next_code (row));
                var click = new GestureClick ();
                click.button = Gdk.BUTTON_SECONDARY;
                click.pressed.connect ((n, x, y) => row_menu (row, x, y));
                row.add_controller (click);
                var press = new GestureLongPress ();
                press.pressed.connect ((x, y) => row_menu (row, x, y));
                row.add_controller (press);
                var keys = new EventControllerKey ();
                keys.key_pressed.connect ((val, code, state) => {
                    if (val == Gdk.Key.Menu || (val == Gdk.Key.F10 && (state & Gdk.ModifierType.SHIFT_MASK) != 0)) {
                        row_menu (row, row.get_width () / 2, row.get_height () / 2);
                        return true;
                    }
                    if (val == Gdk.Key.Delete) {
                        confirm_delete (row.account);
                        return true;
                    }
                    return false;
                });
                row.add_controller (keys);
                rows.add (row);
                list.append (row);
            }
            rebuild_tags ();
            if (!loaded || locked) return;
            show_page (store.items.size == 0 ? "welcome" : "list");
            sync_empty_search ();
            tick ();
        }

        private void sync_empty_search () {
            if (filter == "") {
                list_stack.visible_child_name = "list";
                return;
            }
            bool any = false;
            foreach (var r in rows) {
                if (matches (r.account)) {
                    any = true;
                    break;
                }
            }
            list_stack.visible_child_name = any ? "list" : "none";
        }

        private bool matches (Account a) {
            if (tag_filter != null && !a.has_tag (tag_filter)) return false;
            if (filter == "") return true;
            if (a.issuer.down ().contains (filter) || a.name.down ().contains (filter)) return true;
            foreach (string t in a.tags) if (t.down ().contains (filter)) return true;
            return false;
        }

        private void rebuild_tags () {
            string[] tags = store.all_tags ();
            if (tag_filter != null) {
                string? kept = null;
                foreach (string t in tags) if (t.casefold () == tag_filter.casefold ()) kept = t;
                tag_filter = kept;
            }
            bool same = tags.length == shown_tags.length;
            for (int i = 0; same && i < tags.length; i++) same = tags[i] == shown_tags[i];
            if (!same) {
                tag_bar.remove_chip ("");
                foreach (string t in shown_tags) tag_bar.remove_chip (t);
                shown_tags = tags;
                if (tags.length > 0) {
                    tag_bar.add_chip ("", _("All"));
                    tag_bar.set_chip_closable ("", false);
                    foreach (string t in tags) {
                        tag_bar.add_chip (t, t);
                        tag_bar.set_chip_closable (t, false);
                    }
                }
            }
            tag_bar.visible = tags.length > 0;
            tag_bar.set_active (tag_filter ?? "");
            sync_lock_actions ();
        }

        private void set_tag_filter (string? tag) {
            tag_filter = tag;
            tag_bar.set_active (tag ?? "");
            list.invalidate_filter ();
            sync_empty_search ();
        }

        private void step_tag (int delta) {
            if (shown_tags.length == 0) return;
            int n = shown_tags.length + 1;
            int at = 0;
            for (int i = 0; tag_filter != null && i < shown_tags.length; i++) {
                if (shown_tags[i] == tag_filter) at = i + 1;
            }
            at = ((at + delta) % n + n) % n;
            set_tag_filter (at == 0 ? null : shown_tags[at - 1]);
        }

        private void tag_menu (string tag) {
            if (tag == "") return;
            var chip = tag_bar.get_chip_widget (tag);
            if (chip == null) return;
            var menu = new ContextMenu (chip);
            menu.add_item (_("Rename Tag…"), "document-edit-symbolic", () => rename_tag (tag));
            menu.add_separator ();
            menu.add_item (_("Remove Tag"), "user-trash-symbolic", () => confirm_remove_tag (tag), "destructive");
            menu.closed.connect (() => Idle.add (() => {
                menu.unparent ();
                return Source.REMOVE;
            }));
            menu.popup ();
        }

        private void rename_tag (string tag) {
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Rename Tag"), null, null, _("Rename"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            var group = new PreferencesGroup ();
            var entry = new EntryRow (_("Name"));
            entry.text = tag;
            group.add_row (entry);
            dlg.custom_area.append (group);
            entry.entry_changed.connect (() => dlg.primary_sensitive = Account.clean_tag (entry.text) != "");
            entry.entry_activated.connect (() => {
                if (Account.clean_tag (entry.text) == "") return;
                string name = entry.text;
                dlg.close_dialog ();
                apply_rename (tag, name);
            });
            dlg.response.connect ((r) => {
                if (r == ConfirmDialog.Response.PRIMARY) apply_rename (tag, entry.text);
            });
            dlg.present ();
            entry.grab_focus ();
        }

        private void apply_rename (string tag, string text) {
            string name = Account.clean_tag (text);
            if (name == "" || name == tag) return;
            if (tag_filter == tag) tag_filter = name;
            store.rename_tag (tag, name);
        }

        private void confirm_remove_tag (string tag) {
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Remove the Tag %s?").printf (tag), null,
                _("The tag is taken off every account. The accounts themselves stay."), _("Remove"), ConfirmDialog.ActionStyle.DESTRUCTIVE);
            dlg.transient_for = this;
            dlg.modal = true;
            dlg.response.connect ((r) => {
                if (r != ConfirmDialog.Response.PRIMARY) return;
                if (tag_filter == tag) tag_filter = null;
                store.remove_tag (tag);
            });
            dlg.present ();
        }

        private void tick () {
            if (locked || !loaded) return;
            int64 now = new DateTime.now_utc ().to_unix ();
            foreach (var r in rows) r.tick (now);
        }

        private void copy_code (AccountRow row) {
            string? code = row.current_code ();
            if (code == null) {
                show_toast (_("This account has no secret key"));
                return;
            }
            var clipboard = get_clipboard ();
            set_secret (clipboard, code);
            show_toast (_("Code copied"));
            if (!config.clear_clipboard) return;
            Timeout.add_seconds (45, () => {
                clipboard.read_text_async.begin (null, (o, res) => {
                    try {
                        string? now = clipboard.read_text_async.end (res);
                        if (now == code) clipboard.set_text ("");
                    } catch (Error e) {
                    }
                });
                return Source.REMOVE;
            });
        }

        public static void set_secret (Gdk.Clipboard clipboard, string text) {
            clipboard.set_content (new Gdk.ContentProvider.union ({
                new Gdk.ContentProvider.for_value (text),
                new Gdk.ContentProvider.for_bytes ("x-kde-passwordManagerHint", new Bytes ("secret".data))
            }));
        }

        private Account? pending_prefill = null;

        public void reveal_when_ready (string id) {
            pending_account = id;
            reveal_pending ();
        }

        public void add_prefilled_when_ready (Account account) {
            pending_prefill = account;
            pending_add = true;
            reveal_pending ();
        }

        public void add_when_ready () {
            pending_add = true;
            reveal_pending ();
        }

        private void reveal_pending () {
            if (pending_add && secrets_ready) {
                pending_add = false;
                var prefill = pending_prefill;
                pending_prefill = null;
                edit_account (null, prefill);
            }
            if (pending_account == null || !is_active || !secrets_ready) return;
            string id = pending_account;
            pending_account = null;
            foreach (var r in rows) {
                if (r.account.id == id) {
                    if (filter != "") search_bubble.clear ();
                    set_tag_filter (null);
                    focus_visible = true;
                    r.grab_focus ();
                    show_toast (_("Press Enter to copy the code for %s").printf (r.account.title ()));
                    return;
                }
            }
        }

        private void toggle_favorite (Account a) {
            if (!a.favorite) {
                int count = 0;
                foreach (var other in store.items) if (other.favorite) count++;
                if (count >= AuthenticatorApp.DOCK_FAVORITES) {
                    show_toast (_("The dock menu holds up to three accounts"));
                    return;
                }
            }
            a.favorite = !a.favorite;
            store.update_meta (a);
            show_toast (a.favorite ? _("Added to the dock menu") : _("Removed from the dock menu"));
        }

        private void next_code (AccountRow row) {
            row.account.counter++;
            store.update_meta (row.account);
        }

        private void row_menu (AccountRow row, double x, double y) {
            var a = row.account;
            var menu = new ContextMenu (row);
            menu.pointing_to = { (int) x, (int) y, 1, 1 };
            menu.add_item (_("Copy Code"), "edit-copy-symbolic", () => copy_code (row));
            if (a.kind == Kind.HOTP) menu.add_item (_("Next Code"), "view-refresh-symbolic", () => next_code (row));
            menu.add_item (_("Edit"), "document-edit-symbolic", () => edit_account (a));
            menu.add_item (a.favorite ? _("Remove from Dock Menu") : _("Add to Dock Menu"), a.favorite ? "non-starred-symbolic" : "starred-symbolic", () => toggle_favorite (a));
            if (a.secret != "") {
                menu.add_item (_("Show QR Code"), "phone-symbolic", () => show_qr (a));
                menu.add_item (_("Copy Setup Link"), "insert-link-symbolic", () => {
                    set_secret (get_clipboard (), a.to_uri ());
                    show_toast (_("Setup link copied. It contains the secret key."));
                });
            }
            menu.add_separator ();
            menu.add_item (_("Delete"), "user-trash-symbolic", () => confirm_delete (a), "destructive");
            menu.closed.connect (() => Idle.add (() => {
                menu.unparent ();
                return Source.REMOVE;
            }));
            menu.popup ();
        }

        private void confirm_delete (Account a) {
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Delete %s?").printf (a.title ()), "user-trash-symbolic",
                _("The secret key is removed from the keyring. Make sure you can still sign in to this account, for example with another device or recovery codes."),
                _("Delete"), ConfirmDialog.ActionStyle.DESTRUCTIVE);
            dlg.transient_for = this;
            dlg.modal = true;
            dlg.response.connect ((r) => {
                if (r == ConfirmDialog.Response.PRIMARY) store.remove.begin (a);
            });
            dlg.present ();
        }

        private delegate void Validator ();

        public void edit_account (Account? existing, Account? prefill = null) {
            bool is_new = existing == null;
            var a = is_new ? (prefill != null ? prefill.copy () : new Account ()) : existing.copy ();
            var dlg = new ConfirmDialog ((Gtk.Application) application, is_new ? _("Add Account") : _("Edit Account"), null, null,
                is_new ? _("Add") : _("Save"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            dlg.set_default_size (460, 0);

            var link_group = new PreferencesGroup ();
            var link = new EntryRow (_("Setup Link"));
            link.subtitle = _("Paste an otpauth:// link to fill in everything");
            link_group.add_row (link);
            if (is_new) dlg.custom_area.append (link_group);

            var group = new PreferencesGroup ();
            var issuer = new EntryRow (_("Provider"));
            issuer.text = a.issuer;
            var name = new EntryRow (_("Account"));
            name.text = a.name;
            var secret = new PasswordRow (_("Secret Key"));
            secret.text = a.secret;
            group.add_row (issuer);
            group.add_row (name);
            group.add_row (secret);
            dlg.custom_area.append (group);

            var tag_group = new PreferencesGroup ();
            var tags = new EntryRow (_("Tags"));
            tags.subtitle = _("Separate tags with commas, for example Work, Personal");
            tags.text = a.tags_text ();
            tag_group.add_row (tags);
            dlg.custom_area.append (tag_group);

            string[] kinds = { _("Time-Based (TOTP)"), _("Counter-Based (HOTP)"), _("Steam Guard") };
            string[] algs = { "SHA-1", "SHA-256", "SHA-512" };
            var advanced = new PreferencesGroup ();
            var expander = new ExpanderRow (_("Advanced"), _("Type, algorithm, digits and period"));
            var kind_row = new SelectionRow (_("Type"), kinds, kinds[(int) a.kind]);
            var alg_row = new SelectionRow (_("Algorithm"), algs, algs[(int) a.algorithm]);
            var digits_row = new SpinRow (_("Digits"), null, 6, 8, 1, a.digits.clamp (6, 8));
            var period_row = new SpinRow (_("Period"), _("Seconds each code is valid"), 1, 3600, 1, a.period);
            var counter_row = new SpinRow (_("Counter"), _("Number of codes already used"), 0, 999999999, 1, (double) a.counter);
            expander.add_row (kind_row);
            expander.add_row (alg_row);
            expander.add_row (digits_row);
            expander.add_row (period_row);
            expander.add_row (counter_row);
            advanced.add_row (expander);
            dlg.custom_area.append (advanced);

            var hint = new Label ("");
            hint.add_css_class ("dim-label");
            hint.add_css_class ("caption");
            hint.wrap = true;
            hint.max_width_chars = 46;
            hint.justify = Justification.CENTER;
            dlg.custom_area.append (hint);

            if (is_new && Qr.AVAILABLE) {
                var scan = new Button.with_label (_("Scan QR Code from an Image…"));
                scan.add_css_class ("flat");
                scan.halign = Align.CENTER;
                scan.clicked.connect (() => {
                    dlg.close_dialog ();
                    import_qr ();
                });
                dlg.custom_area.append (scan);
            }

            Validator validate = () => {
                a.issuer = issuer.text.strip ();
                a.name = name.text.strip ();
                a.secret = Base32.clean (secret.text);
                a.set_tags_text (tags.text);
                for (int i = 0; i < kinds.length; i++) if (kind_row.current_value == kinds[i]) a.kind = (Kind) i;
                for (int i = 0; i < algs.length; i++) if (alg_row.current_value == algs[i]) a.algorithm = (Algorithm) i;
                a.digits = (int) digits_row.value;
                a.period = (int) period_row.value;
                a.counter = (uint64) counter_row.value;
                bool steam = a.kind == Kind.STEAM;
                alg_row.visible = !steam;
                digits_row.visible = !steam;
                period_row.visible = a.kind == Kind.TOTP;
                counter_row.visible = a.kind == Kind.HOTP;
                string? problem = null;
                if (a.issuer == "" && a.name == "") problem = _("Enter the provider or the account name.");
                else if (secret.text.strip () == "") problem = _("Enter the secret key shown by the provider when you turned on two-factor sign-in.");
                else problem = a.validate ();
                dlg.primary_sensitive = problem == null;
                if (problem != null) {
                    hint.label = problem;
                } else {
                    string code = a.code (new DateTime.now_utc ().to_unix ()) ?? "";
                    hint.label = _("The current code is %s").printf (Account.group_code (code));
                }
            };
            issuer.entry_changed.connect (() => validate ());
            name.entry_changed.connect (() => validate ());
            secret.entry_changed.connect (() => validate ());
            kind_row.selected.connect ((item) => {
                kind_row.current_value = item;
                validate ();
            });
            alg_row.selected.connect ((item) => {
                alg_row.current_value = item;
                validate ();
            });
            digits_row.spin_btn.value_changed.connect (() => validate ());
            period_row.spin_btn.value_changed.connect (() => validate ());
            counter_row.spin_btn.value_changed.connect (() => validate ());
            link.entry_changed.connect (() => {
                string t = link.text.strip ();
                if (t == "") {
                    link.subtitle = _("Paste an otpauth:// link to fill in everything");
                    return;
                }
                if (Migration.is_migration (t)) {
                    try {
                        var batch = Migration.parse (t);
                        dlg.close_dialog ();
                        confirm_import (batch, _("Google Authenticator"));
                    } catch (AccountError e) {
                        link.subtitle = e.message;
                    }
                    return;
                }
                try {
                    var parsed = Account.parse_uri (t);
                    issuer.text = parsed.issuer;
                    name.text = parsed.name;
                    secret.text = parsed.secret;
                    kind_row.current_value = kinds[(int) parsed.kind];
                    alg_row.current_value = algs[(int) parsed.algorithm];
                    digits_row.value = parsed.kind == Kind.STEAM ? 6 : parsed.digits;
                    period_row.value = parsed.period;
                    counter_row.value = (double) parsed.counter;
                    link.subtitle = _("Link read");
                    validate ();
                } catch (AccountError e) {
                    link.subtitle = e.message;
                }
            });
            validate ();

            dlg.response.connect ((r) => {
                if (r != ConfirmDialog.Response.PRIMARY) return;
                validate ();
                if (a.validate () != null) return;
                if (is_new) {
                    var dup = store.find_same (a);
                    if (dup != null) {
                        show_toast (_("%s is already in your accounts").printf (dup.title ()));
                        return;
                    }
                }
                store.put.begin (a, (o, res) => {
                    try {
                        store.put.end (res);
                        show_toast (is_new ? _("Account added") : _("Account saved"));
                    } catch (Error e) {
                        show_message (_("Could Not Save the Account"), e.message);
                    }
                });
            });
            dlg.present ();
            if (is_new && prefill == null) link.grab_focus ();
            else issuer.grab_focus ();
        }

        private void show_message (string title, string text) {
            var dlg = new ConfirmDialog.message ((Gtk.Application) application, title, "dialog-error", text);
            dlg.transient_for = this;
            dlg.modal = true;
            dlg.present ();
        }

        public void import_file () {
            var dialog = new FileDialog ();
            dialog.title = _("Import Accounts");
            var filters = new GLib.ListStore (typeof (FileFilter));
            var all = new FileFilter ();
            all.name = _("Backups and Link Lists");
            all.add_suffix ("json");
            all.add_suffix ("txt");
            all.add_mime_type ("application/json");
            all.add_mime_type ("text/plain");
            filters.append (all);
            dialog.filters = filters;
            dialog.open.begin (this, null, (o, res) => {
                try {
                    var file = dialog.open.end (res);
                    if (file == null) return;
                    uint8[] data;
                    file.load_contents (null, out data, null);
                    if (data.length > 8 * 1024 * 1024) throw new AccountError.INVALID (_("The file is too large."));
                    string text = (string) data;
                    if (!text.validate ()) throw new AccountError.INVALID (_("The file is not a text file."));
                    string filename = file.get_basename () ?? "";
                    ImportResult result;
                    try {
                        result = Transfer.parse (text);
                    } catch (AccountError.ENCRYPTED e) {
                        ask_backup_password (text, filename, null);
                        return;
                    }
                    confirm_import (result, filename);
                } catch (Error e) {
                    if (e is IOError.CANCELLED || e is Gtk.DialogError.DISMISSED || e is Gtk.DialogError.CANCELLED) return;
                    show_message (_("Could Not Import"), e.message);
                }
            });
        }

        public void import_qr () {
            if (!Qr.AVAILABLE) return;
            var dialog = new FileDialog ();
            dialog.title = _("Scan a QR Code");
            var filters = new GLib.ListStore (typeof (FileFilter));
            var images = new FileFilter ();
            images.name = _("Images");
            images.add_pixbuf_formats ();
            filters.append (images);
            dialog.filters = filters;
            dialog.open.begin (this, null, (o, res) => {
                try {
                    var file = dialog.open.end (res);
                    if (file == null || file.get_path () == null) return;
                    string[] codes = Qr.decode_file (file.get_path ());
                    if (codes.length == 0) {
                        show_message (_("No QR Code Found"), _("Use a sharp picture where the whole QR code is visible."));
                        return;
                    }
                    var result = new ImportResult ();
                    result.format = "QR";
                    string? last_error = null;
                    bool migration = false;
                    foreach (string c in codes) {
                        try {
                            if (Migration.is_migration (c)) {
                                var batch = Migration.parse (c);
                                migration = true;
                                result.accounts.add_all (batch.accounts);
                                result.skipped += batch.skipped;
                                if (batch.batch_size > 1) result.note = _("This is code %d of %d from Google Authenticator. Scan the other codes too to add every account.").printf (batch.batch_index + 1, batch.batch_size);
                            } else {
                                result.accounts.add (Account.parse_uri (c));
                            }
                        } catch (AccountError e) {
                            result.skipped++;
                            last_error = e.message;
                        }
                    }
                    if (result.accounts.size == 0) {
                        show_message (_("Not a Setup Code"), last_error ?? _("The QR code does not contain an otpauth:// link."));
                        return;
                    }
                    if (result.accounts.size == 1 && result.skipped == 0 && !migration) {
                        edit_account (null, result.accounts[0]);
                        return;
                    }
                    confirm_import (result, file.get_basename () ?? "");
                } catch (Error e) {
                    if (e is IOError.CANCELLED || e is Gtk.DialogError.DISMISSED || e is Gtk.DialogError.CANCELLED) return;
                    show_message (_("Could Not Read the Image"), e.message);
                }
            });
        }

        private void confirm_import (ImportResult result, string filename) {
            var fresh = new Gee.ArrayList<Account> ();
            int duplicates = 0;
            foreach (var a in result.accounts) {
                bool dup = store.find_same (a) != null;
                foreach (var f in fresh) if (f.same_as (a)) dup = true;
                if (dup) duplicates++;
                else fresh.add (a);
            }
            if (fresh.size == 0) {
                show_message (_("Nothing to Import"), duplicates > 0 ? _("All the accounts in %s are already here.").printf (filename) : _("%s has no accounts that can be used.").printf (filename));
                return;
            }
            var sb = new StringBuilder ();
            sb.append (ngettext ("%d account from %s will be added.", "%d accounts from %s will be added.", fresh.size).printf (fresh.size, filename));
            if (duplicates > 0) sb.append (" " + ngettext ("%d is already here and is skipped.", "%d are already here and are skipped.", duplicates).printf (duplicates));
            if (result.skipped > 0) sb.append (" " + ngettext ("%d entry could not be read.", "%d entries could not be read.", result.skipped).printf (result.skipped));
            var batch = result as MigrationResult;
            if (result.note == "" && batch != null && batch.batch_size > 1) result.note = _("This is code %d of %d from Google Authenticator. Scan the other codes too to add every account.").printf (batch.batch_index + 1, batch.batch_size);
            if (result.note != "") sb.append ("\n\n" + result.note);
            var dlg = new ConfirmDialog ((Gtk.Application) application, ngettext ("Import %d Account?", "Import %d Accounts?", fresh.size).printf (fresh.size),
                "dev.sinty.authenticator", sb.str, _("Import"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            dlg.response.connect ((r) => {
                if (r != ConfirmDialog.Response.PRIMARY) return;
                import_all.begin (fresh);
            });
            dlg.present ();
        }

        private async void import_all (Gee.List<Account> accounts) {
            int done = 0;
            string? failure = null;
            foreach (var a in accounts) {
                try {
                    yield store.put (a);
                    done++;
                } catch (Error e) {
                    failure = e.message;
                    break;
                }
            }
            if (failure != null) show_message (_("Import Stopped"), _("%d accounts were added before an error: %s").printf (done, failure));
            else show_toast (ngettext ("%d account imported", "%d accounts imported", done).printf (done));
        }

        public void export_accounts () {
            if (store.items.size == 0) {
                show_toast (_("There are no accounts to export"));
                return;
            }
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Export Accounts"), "dialog-warning", null,
                _("Export…"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            var format = new SegmentedControl ();
            format.add_option ("encrypted", _("Encrypted Backup"));
            format.add_option ("aegis", _("Aegis Backup"));
            format.add_option ("uri", _("List of Links"));
            format.halign = Align.CENTER;
            var about = new Label ("");
            about.wrap = true;
            about.max_width_chars = 42;
            about.justify = Justification.CENTER;
            dlg.custom_area.append (about);
            dlg.custom_area.append (format);
            format.selected.connect ((kind) => {
                about.label = kind == "encrypted"
                    ? _("All your accounts in one file locked with a password you choose. Authenticator and Aegis can restore it.")
                    : _("The file will contain all your secret keys without encryption. Anyone who reads it can create your codes. Keep it safe and delete it when you no longer need it.");
            });
            format.set_active ("encrypted");
            about.label = _("All your accounts in one file locked with a password you choose. Authenticator and Aegis can restore it.");
            dlg.response.connect ((r) => {
                if (r != ConfirmDialog.Response.PRIMARY) return;
                string kind = format.active_option ?? "encrypted";
                if (kind == "encrypted") start_backup ();
                else save_export (kind);
            });
            dlg.present ();
        }

        public void start_backup () {
            if (store.items.size == 0) {
                show_toast (_("There are no accounts to back up"));
                return;
            }
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Back Up with a Password"), "dialog-password",
                _("Choose a password for the backup. You need it to restore the accounts, and it cannot be recovered."),
                _("Save Backup…"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            var group = new PreferencesGroup ();
            var first = new PasswordRow (_("Backup Password"));
            var second = new PasswordRow (_("Confirm Password"));
            group.add_row (first);
            group.add_row (second);
            dlg.custom_area.append (group);
            var hint = new Label (_("Use at least 8 characters"));
            hint.add_css_class ("dim-label");
            hint.add_css_class ("caption");
            dlg.custom_area.append (hint);
            dlg.primary_sensitive = false;
            Validator check = () => {
                bool long_enough = first.text.char_count () >= 8;
                bool same = first.text == second.text;
                dlg.primary_sensitive = long_enough && same;
                hint.label = !long_enough ? _("Use at least 8 characters") : (!same ? _("The passwords do not match") : _("Ready"));
            };
            first.entry_changed.connect (() => check ());
            second.entry_changed.connect (() => check ());
            second.entry_activated.connect (() => {
                if (!dlg.primary_sensitive) return;
                string pw = first.text;
                dlg.close_dialog ();
                save_backup (pw);
            });
            dlg.response.connect ((r) => {
                if (r == ConfirmDialog.Response.PRIMARY) save_backup (first.text);
            });
            dlg.present ();
            first.grab_focus ();
        }

        private void save_backup (string password) {
            var dialog = new FileDialog ();
            dialog.title = _("Save Encrypted Backup");
            dialog.initial_name = "authenticator-backup-%s.json".printf (new DateTime.now_local ().format ("%Y-%m-%d"));
            var accounts = store.sorted ();
            dialog.save.begin (this, null, (o, res) => {
                File file;
                try {
                    file = dialog.save.end (res);
                } catch (Error e) {
                    return;
                }
                if (file == null) return;
                show_toast (_("Encrypting the backup…"));
                seal_async.begin (accounts, password, (o2, res2) => {
                    try {
                        string text = seal_async.end (res2);
                        var stream = file.replace (null, false, FileCreateFlags.PRIVATE | FileCreateFlags.REPLACE_DESTINATION, null);
                        stream.write_all (text.data, null, null);
                        stream.close (null);
                        show_toast (ngettext ("%d account backed up", "%d accounts backed up", accounts.size).printf (accounts.size));
                    } catch (Error e) {
                        show_message (_("Could Not Save the Backup"), e.message);
                    }
                });
            });
        }

        private async string seal_async (Gee.List<Account> accounts, string password) throws Error {
            SourceFunc callback = seal_async.callback;
            string result = "";
            Error? failure = null;
            new Thread<void> ("auth-seal", () => {
                try {
                    result = Transfer.export_aegis_encrypted (accounts, password);
                } catch (Error e) {
                    failure = e;
                }
                Idle.add ((owned) callback);
            });
            yield;
            if (failure != null) throw failure;
            return result;
        }

        private async ImportResult open_async (string text, string password) throws Error {
            SourceFunc callback = open_async.callback;
            ImportResult? result = null;
            Error? failure = null;
            new Thread<void> ("auth-open", () => {
                try {
                    result = Transfer.parse_aegis_encrypted (text, password);
                } catch (Error e) {
                    failure = e;
                }
                Idle.add ((owned) callback);
            });
            yield;
            if (failure != null) throw failure;
            return result;
        }

        private void ask_backup_password (string text, string filename, string? problem) {
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Encrypted Backup"), "dialog-password",
                _("Enter the password of %s.").printf (filename), _("Open"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = this;
            dlg.modal = true;
            var group = new PreferencesGroup ();
            var entry = new PasswordRow (_("Backup Password"));
            group.add_row (entry);
            dlg.custom_area.append (group);
            var error_label = new Label (problem ?? "");
            error_label.add_css_class ("error");
            error_label.wrap = true;
            error_label.justify = Justification.CENTER;
            error_label.visible = problem != null;
            dlg.custom_area.append (error_label);
            dlg.primary_sensitive = false;
            entry.entry_changed.connect (() => {
                dlg.primary_sensitive = entry.text != "";
                error_label.visible = false;
            });
            entry.entry_activated.connect (() => {
                if (entry.text == "") return;
                string pw = entry.text;
                dlg.close_dialog ();
                unlock_backup (text, filename, pw);
            });
            dlg.response.connect ((r) => {
                if (r == ConfirmDialog.Response.PRIMARY) unlock_backup (text, filename, entry.text);
            });
            dlg.present ();
            entry.grab_focus ();
        }

        private void unlock_backup (string text, string filename, string password) {
            show_toast (_("Opening the backup…"));
            open_async.begin (text, password, (o, res) => {
                try {
                    var result = open_async.end (res);
                    confirm_import (result, filename);
                } catch (VaultError.WRONG_PASSWORD e) {
                    ask_backup_password (text, filename, e.message);
                } catch (Error e) {
                    show_message (_("Could Not Open the Backup"), e.message);
                }
            });
        }

        private void show_qr (Account a) {
            QrCode qr;
            try {
                qr = QrCode.encode_text (a.to_uri (), EcLevel.MEDIUM);
            } catch (EncodeError e) {
                show_message (_("Could Not Make the QR Code"), _("The account details are too long for a QR code."));
                return;
            }
            var dlg = new AppDialog ((Gtk.Application) application, true);
            dlg.set_title (_("Scan with Your Phone"));
            dlg.transient_for = this;
            dlg.set_default_size (420, 0);
            var box = new Box (Orientation.VERTICAL, 14);
            box.margin_top = 20;
            box.margin_bottom = 24;
            box.margin_start = 28;
            box.margin_end = 28;
            var warn = new Box (Orientation.HORIZONTAL, 10);
            warn.halign = Align.CENTER;
            var warn_icon = new Image.from_icon_name ("dialog-warning");
            warn_icon.pixel_size = 32;
            warn_icon.valign = Align.CENTER;
            warn.append (warn_icon);
            var warn_label = new Label (_("Anyone who sees this code can copy the account and create its sign-in codes. Show it only to your own phone."));
            warn_label.wrap = true;
            warn_label.max_width_chars = 38;
            warn_label.xalign = 0;
            warn.append (warn_label);
            box.append (warn);
            int module = Render.module_for_size (qr, 288);
            var surface = Render.surface (qr, module);
            var picture = new Picture.for_paintable (texture_from_surface (surface));
            picture.can_shrink = false;
            picture.halign = Align.CENTER;
            picture.overflow = Overflow.HIDDEN;
            picture.add_css_class ("card");
            picture.update_property (Gtk.AccessibleProperty.LABEL, _("QR code for %s").printf (a.title ()), -1);
            box.append (picture);
            var title = new Label (a.title ());
            title.add_css_class ("title-3");
            title.ellipsize = Pango.EllipsizeMode.END;
            box.append (title);
            if (a.subtitle () != "") {
                var sub = new Label (a.subtitle ());
                sub.add_css_class ("dim-label");
                sub.ellipsize = Pango.EllipsizeMode.END;
                box.append (sub);
            }
            var done = new Button.with_label (_("Done"));
            done.add_css_class ("pill");
            done.add_css_class ("suggested-action");
            done.halign = Align.CENTER;
            done.width_request = 140;
            done.margin_top = 6;
            done.clicked.connect (() => dlg.close_dialog ());
            dlg.set_cancel_button (done);
            box.append (done);
            dlg.content_box.append (box);
            secret_windows.add (dlg);
            dlg.close_request.connect (() => {
                secret_windows.remove (dlg);
                return false;
            });
            dlg.present ();
            done.grab_focus ();
        }

        private static Gdk.Texture texture_from_surface (Cairo.ImageSurface surface) {
            int w = surface.get_width (), h = surface.get_height (), stride = surface.get_stride ();
            unowned uint8[] data = surface.get_data ();
            data.length = stride * h;
            var bytes = new Bytes (data);
            return new Gdk.MemoryTexture (w, h, Gdk.MemoryFormat.B8G8R8X8, bytes, stride);
        }

        private void save_export (string kind) {
            var dialog = new FileDialog ();
            dialog.title = _("Export Accounts");
            string date = new DateTime.now_local ().format ("%Y-%m-%d");
            dialog.initial_name = kind == "aegis" ? "authenticator-%s.json".printf (date) : "authenticator-%s.txt".printf (date);
            dialog.save.begin (this, null, (o, res) => {
                try {
                    var file = dialog.save.end (res);
                    if (file == null) return;
                    string text = kind == "aegis" ? Transfer.export_aegis (store.sorted ()) : Transfer.export_uri_list (store.sorted ());
                    var stream = file.replace (null, false, FileCreateFlags.PRIVATE | FileCreateFlags.REPLACE_DESTINATION, null);
                    stream.write_all (text.data, null, null);
                    stream.close (null);
                    show_toast (_("Accounts exported"));
                } catch (Error e) {
                    if (e is IOError.CANCELLED || e is Gtk.DialogError.DISMISSED || e is Gtk.DialogError.CANCELLED) return;
                    show_message (_("Could Not Export"), e.message);
                }
            });
        }

        private void enter_locked () {
            locked = true;
            foreach (var w in secret_windows.to_array ()) w.close ();
            secret_windows.clear ();
            store.forget_secrets ();
            Widget? child;
            while ((child = list.get_first_child ()) != null) list.remove (child);
            rows.clear ();
            bool pw = applied_mode == LockMode.PASSWORD;
            unlock_password_box.visible = pw;
            unlock_entry.text = "";
            unlock_error.visible = false;
            unlock_button.sensitive = true;
            unlock_button.label = pw ? _("Unlock") : _("Unlock with the Keyring");
            show_page ("locked");
            if (pw) unlock_entry.grab_focus ();
            else unlock_button.grab_focus ();
        }

        public void lock_now () {
            if (applied_mode == LockMode.NONE || locked || !loaded) return;
            if (applied_mode == LockMode.KEYRING) {
                Keyring.lock_default.begin ((o, res) => {
                    try {
                        Keyring.lock_default.end (res);
                    } catch (Error e) {
                        warning ("authenticator: %s", e.message);
                    }
                });
            }
            enter_locked ();
        }

        private void try_unlock () {
            if (!locked) return;
            unlock_button.sensitive = false;
            if (applied_mode == LockMode.KEYRING) {
                Keyring.unlock_default.begin ((o, res) => {
                    bool ok = false;
                    try {
                        ok = Keyring.unlock_default.end (res);
                    } catch (Error e) {
                        unlock_error.label = e.message;
                        unlock_error.visible = true;
                    }
                    unlock_button.sensitive = true;
                    if (ok) load_secrets.begin ();
                });
                return;
            }
            string attempt = unlock_entry.text;
            Keyring.lookup_lock.begin ((o, res) => {
                string? stored = null;
                try {
                    stored = Keyring.lookup_lock.end (res);
                } catch (Error e) {
                    unlock_button.sensitive = true;
                    unlock_error.label = e.message;
                    unlock_error.visible = true;
                    return;
                }
                if (stored == null) {
                    applied_mode = LockMode.NONE;
                    config.lock_mode = LockMode.NONE;
                    load_secrets.begin ();
                    return;
                }
                verify_async.begin (attempt, stored, (o2, res2) => {
                    bool ok = verify_async.end (res2);
                    unlock_button.sensitive = true;
                    if (ok) {
                        unlock_entry.text = "";
                        load_secrets.begin ();
                    } else {
                        unlock_error.label = _("The password is not correct");
                        unlock_error.visible = true;
                        unlock_entry.grab_focus ();
                    }
                });
            });
        }

        private async bool verify_async (string attempt, string stored) {
            SourceFunc callback = verify_async.callback;
            bool ok = false;
            new Thread<void> ("auth-verify", () => {
                ok = PasswordHash.verify (attempt, stored);
                Idle.add ((owned) callback);
            });
            yield;
            return ok;
        }

        private async string hash_async (string password) {
            SourceFunc callback = hash_async.callback;
            string result = "";
            new Thread<void> ("auth-hash", () => {
                result = PasswordHash.create (password);
                Idle.add ((owned) callback);
            });
            yield;
            return result;
        }

        private void schedule_idle_lock () {
            if (idle_lock_id != 0) Source.remove (idle_lock_id);
            idle_lock_id = 0;
            if (is_active || applied_mode == LockMode.NONE || locked) return;
            idle_lock_id = Timeout.add_seconds (config.lock_minutes * 60, () => {
                idle_lock_id = 0;
                if (!is_active) lock_now ();
                return Source.REMOVE;
            });
        }

        private void ask_new_password (Gtk.Window parent, owned Validator done, owned Validator cancelled) {
            var dlg = new ConfirmDialog ((Gtk.Application) application, _("Set a Password"), "dialog-password",
                _("You will need it every time you open Authenticator. It cannot be recovered, but your accounts stay in the keyring."),
                _("Set Password"), ConfirmDialog.ActionStyle.SUGGESTED);
            dlg.transient_for = parent;
            dlg.modal = true;
            var group = new PreferencesGroup ();
            var first = new PasswordRow (_("New Password"));
            var second = new PasswordRow (_("Confirm Password"));
            group.add_row (first);
            group.add_row (second);
            dlg.custom_area.append (group);
            var hint = new Label (_("Use at least 6 characters"));
            hint.add_css_class ("dim-label");
            hint.add_css_class ("caption");
            dlg.custom_area.append (hint);
            dlg.primary_sensitive = false;
            Validator check = () => {
                bool long_enough = first.text.char_count () >= 6;
                bool same = first.text == second.text;
                dlg.primary_sensitive = long_enough && same;
                hint.label = !long_enough ? _("Use at least 6 characters") : (!same ? _("The passwords do not match") : _("Ready"));
            };
            first.entry_changed.connect (() => check ());
            second.entry_changed.connect (() => check ());
            bool answered = false;
            dlg.close_request.connect (() => {
                if (!answered) {
                    answered = true;
                    cancelled ();
                }
                return false;
            });
            dlg.response.connect ((r) => {
                answered = true;
                if (r != ConfirmDialog.Response.PRIMARY) {
                    cancelled ();
                    return;
                }
                string pw = first.text;
                hash_async.begin (pw, (o, res) => {
                    string hash = hash_async.end (res);
                    Keyring.store_lock.begin (hash, (o2, res2) => {
                        try {
                            Keyring.store_lock.end (res2);
                            done ();
                        } catch (Error e) {
                            show_message (_("Could Not Set the Password"), e.message);
                            cancelled ();
                        }
                    });
                });
            });
            dlg.present ();
            first.grab_focus ();
        }

        private void show_toast (string text) {
            if (last_toast != null) last_toast.dismiss ();
            last_toast = new Singularity.Widgets.Toast (text);
            last_toast.timeout = 3;
            add_toast (last_toast);
        }
    }
}
