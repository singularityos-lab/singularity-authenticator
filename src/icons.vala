using Gtk;

namespace Singularity.Apps.Authenticator {

    namespace Provider {
        private const string[] KNOWN = {
            "google", "google.com", "gmail", "google.com", "github", "github.com", "gitlab", "gitlab.com",
            "microsoft", "microsoft.com", "outlook", "outlook.com", "amazon", "amazon.com", "aws", "aws.amazon.com",
            "apple", "apple.com", "dropbox", "dropbox.com", "facebook", "facebook.com", "meta", "facebook.com",
            "instagram", "instagram.com", "twitter", "x.com", "x", "x.com", "discord", "discord.com",
            "steam", "steampowered.com", "reddit", "reddit.com", "paypal", "paypal.com", "proton", "proton.me",
            "protonmail", "proton.me", "bitwarden", "bitwarden.com", "cloudflare", "cloudflare.com",
            "digitalocean", "digitalocean.com", "linkedin", "linkedin.com", "slack", "slack.com",
            "mastodon", "joinmastodon.org", "nextcloud", "nextcloud.com", "epic games", "epicgames.com",
            "ubisoft", "ubisoft.com", "coinbase", "coinbase.com", "binance", "binance.com", "kraken", "kraken.com",
            "npm", "npmjs.com", "pypi", "pypi.org", "docker", "docker.com", "hetzner", "hetzner.com",
            "tutanota", "tuta.com", "mega", "mega.nz", "twitch", "twitch.tv", "adobe", "adobe.com",
            "zoho", "zoho.com", "yahoo", "yahoo.com", "sourceforge", "sourceforge.net", "codeberg", "codeberg.org"
        };

        public string? domain_for (string issuer) {
            string key = issuer.strip ().down ();
            if (key == "") return null;
            for (int i = 0; i + 1 < KNOWN.length; i += 2) if (KNOWN[i] == key) return KNOWN[i + 1];
            if (key.contains (".") && !key.contains (" ") && !key.contains ("/")) return key;
            var sb = new StringBuilder ();
            for (int i = 0; i < key.length; i++) {
                char c = key[i];
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') sb.append_c (c);
            }
            if (sb.len < 2) return null;
            return sb.str + ".com";
        }

        public string initial (string title) {
            string t = title.strip ();
            if (t == "") return "?";
            unichar c = t.get_char (0);
            return c.toupper ().to_string ();
        }

        public uint hue (string title) {
            return str_hash (title.down ()) % 360;
        }
    }

    public class IconCache : Object {
        private Gee.HashMap<string, Gdk.Texture?> memory = new Gee.HashMap<string, Gdk.Texture?> ();
        private Gee.HashSet<string> pending = new Gee.HashSet<string> ();
        private Soup.Session? session;
        public signal void updated (string domain);

        private static string dir () {
            return Path.build_filename (Environment.get_user_cache_dir (), "singularity-authenticator", "icons");
        }

        private static string file_for (string domain) {
            return Path.build_filename (dir (), domain + ".png");
        }

        public static string? cached_path (string domain) {
            string f = file_for (domain);
            return FileUtils.test (f, FileTest.EXISTS) ? f : null;
        }

        private static string miss_for (string domain) {
            return Path.build_filename (dir (), domain + ".none");
        }

        public Gdk.Texture? get_icon (string domain, bool fetch) {
            if (memory.has_key (domain)) return memory[domain];
            string f = file_for (domain);
            if (FileUtils.test (f, FileTest.EXISTS)) {
                try {
                    var t = Gdk.Texture.from_filename (f);
                    memory[domain] = t;
                    return t;
                } catch (Error e) {
                }
            }
            if (fetch) download.begin (domain);
            return null;
        }

        public void clear () {
            memory.clear ();
            try {
                var d = Dir.open (dir ());
                string? name;
                while ((name = d.read_name ()) != null) FileUtils.remove (Path.build_filename (dir (), name));
            } catch (Error e) {
            }
        }

        private bool recently_missed (string domain) {
            var info = File.new_for_path (miss_for (domain));
            try {
                var fi = info.query_info (FileAttribute.TIME_MODIFIED, FileQueryInfoFlags.NONE);
                var dt = fi.get_modification_date_time ();
                return dt != null && new DateTime.now_utc ().difference (dt) < TimeSpan.DAY * 7;
            } catch (Error e) {
                return false;
            }
        }

        private async Gdk.Texture? try_url (string url) {
            if (session == null) {
                session = new Soup.Session ();
                session.timeout = 10;
                session.user_agent = "Singularity-Authenticator";
            }
            var msg = new Soup.Message ("GET", url);
            if (msg == null) return null;
            try {
                var bytes = yield session.send_and_read_async (msg, Priority.LOW, null);
                if (msg.status_code != 200 || bytes.get_size () < 16 || bytes.get_size () > 512 * 1024) return null;
                var loader = new Gdk.PixbufLoader ();
                loader.write_bytes (bytes);
                loader.close ();
                var pix = loader.get_pixbuf ();
                if (pix == null || pix.width < 16) return null;
                if (pix.width > 128 || pix.height > 128) pix = pix.scale_simple (128, 128, Gdk.InterpType.BILINEAR);
                return Gdk.Texture.for_pixbuf (pix);
            } catch (Error e) {
                return null;
            }
        }

        private async void download (string domain) {
            if (pending.contains (domain) || recently_missed (domain)) return;
            pending.add (domain);
            Gdk.Texture? tex = yield try_url ("https://%s/apple-touch-icon.png".printf (domain));
            if (tex == null) tex = yield try_url ("https://%s/favicon.ico".printf (domain));
            pending.remove (domain);
            DirUtils.create_with_parents (dir (), 0700);
            if (tex == null) {
                try {
                    FileUtils.set_contents (miss_for (domain), "");
                } catch (Error e) {
                }
                return;
            }
            tex.save_to_png (file_for (domain));
            memory[domain] = tex;
            updated (domain);
        }
    }

    public class ProviderAvatar : Widget {
        private int size;
        private string letter = "?";
        private uint hue_value;
        private Gdk.Texture? texture;

        public ProviderAvatar (int size = 40) {
            this.size = size;
            add_css_class ("auth-avatar");
            update_property (Gtk.AccessibleProperty.LABEL, "", -1);
        }

        public void set_account (string title, Gdk.Texture? icon) {
            letter = Provider.initial (title);
            hue_value = Provider.hue (title);
            texture = icon;
            queue_draw ();
        }

        protected override void measure (Orientation orientation, int for_size, out int minimum, out int natural, out int minimum_baseline, out int natural_baseline) {
            minimum = natural = size;
            minimum_baseline = natural_baseline = -1;
        }

        private static Gdk.RGBA hsl (double h, double s, double l) {
            double c = (1 - Math.fabs (2 * l - 1)) * s;
            double hp = h / 60.0;
            double x = c * (1 - Math.fabs (Math.fmod (hp, 2) - 1));
            double r = 0, g = 0, b = 0;
            if (hp < 1) { r = c; g = x; }
            else if (hp < 2) { r = x; g = c; }
            else if (hp < 3) { g = c; b = x; }
            else if (hp < 4) { g = x; b = c; }
            else if (hp < 5) { r = x; b = c; }
            else { r = c; b = x; }
            double m = l - c / 2;
            var rgba = Gdk.RGBA ();
            rgba.red = (float) (r + m);
            rgba.green = (float) (g + m);
            rgba.blue = (float) (b + m);
            rgba.alpha = 1;
            return rgba;
        }

        protected override void snapshot (Gtk.Snapshot snap) {
            float s = (float) int.min (get_width (), get_height ());
            float x = (get_width () - s) / 2;
            float y = (get_height () - s) / 2;
            var rect = Graphene.Rect ().init (x, y, s, s);
            var clip = Gsk.RoundedRect ();
            clip.init_from_rect (rect, s * 0.28f);
            snap.push_rounded_clip (clip);
            if (texture != null) {
                var white = Gdk.RGBA ();
                white.parse ("#ffffff");
                snap.append_color (white, rect);
                float pad = s * 0.14f;
                snap.append_scaled_texture (texture, Gsk.ScalingFilter.TRILINEAR, Graphene.Rect ().init (x + pad, y + pad, s - 2 * pad, s - 2 * pad));
            } else {
                var top = hsl (hue_value, 0.62, 0.58);
                var bottom = hsl ((hue_value + 20) % 360, 0.66, 0.44);
                Gsk.ColorStop[] stops = { { 0f, top }, { 1f, bottom } };
                snap.append_linear_gradient (rect, Graphene.Point ().init (x, y), Graphene.Point ().init (x, y + s), stops);
                var layout = create_pango_layout (letter);
                var font = new Pango.FontDescription ();
                font.set_weight (Pango.Weight.BOLD);
                font.set_absolute_size (s * 0.46 * Pango.SCALE);
                layout.set_font_description (font);
                int lw, lh;
                layout.get_pixel_size (out lw, out lh);
                snap.save ();
                snap.translate (Graphene.Point ().init (x + (s - lw) / 2, y + (s - lh) / 2));
                var white = Gdk.RGBA ();
                white.parse ("#ffffff");
                snap.append_layout (layout, white);
                snap.restore ();
            }
            snap.pop ();
        }
    }
}
