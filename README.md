# singularity-authenticator

> [!IMPORTANT]
> Report bugs and request features in the
> [Singularity Desktop tracker](https://github.com/singularityos-lab/singularity-desktop/issues/new/choose).

Authenticator for the [Singularity Desktop Environment](https://github.com/singularityos-lab): two-factor sign-in codes for your accounts.

## Requirements

- [Meson](https://mesonbuild.com/) ≥ 1.0
- [Vala](https://vala.dev/) compiler
- GTK4, libgee-0.8, json-glib-1.0, libsoup-3.0, libsecret-1, gdk-pixbuf-2.0, libgcrypt, cairo
- [libsingularity](https://github.com/singularityos-lab/libsingularity)

## Build & Install

```sh
meson setup build
meson compile -C build
meson install -C build
```

## Third-party code

- `third_party/zbar/zbar.h`: the public header of the [ZBar](https://github.com/mchehab/zbar) bar code reader, GNU LGPL 2.1 or later, used to call the system library.

## License

GPL-3.0-only - see [LICENSE](LICENSE).

## Use of Generative AI

Maintainers may use generative AI tools as assistants while working on singularity-authenticator. Non-trivial assisted commits disclose the tool, model, and scope of the work.

AI tools may assist with code comments, documentation, repetitive code, and issue triage. Maintainers make project decisions and review every assisted change before it is merged.

Use these trailers for non-trivial assisted commits:

```plain
Assisted-by: <tool>:<model-version>
AI-Scope: <what the tool generated and the prompt or a short prompt summary>
```

Single-line completions, renames, and formatting changes do not need trailers.

Coding agents must also follow [AGENTS.md](AGENTS.md) before changing files,
creating commits, or opening pull requests.
