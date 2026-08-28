//! The command reference in `docs-site/src/reference/cli.md` is rendered
//! from the clap definitions, so it cannot drift from the binary: the
//! `cli_reference_is_current` test compares the committed file against what
//! the current definitions render, and fails with instructions when they
//! differ. `SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference`
//! regenerates the file.
//!
//! Wording rule for everything that ends up here (i.e. the doc comments in
//! `main.rs`): these pages are published on spora.to, so the website's copy
//! guide applies. In particular, no em dashes.

use clap::CommandFactory as _;

const PREAMBLE: &str = "\
<!-- GENERATED FILE, do not edit: this page is rendered from the clap
     definitions in spora-cli/src/main.rs. Change the doc comments there,
     then run: SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference -->

# Command reference

The complete surface of the `spora` command line, rendered from the same
definitions the binary is built from. `spora <command> --help` prints the
same text.

";

pub(crate) fn render_cli_reference() -> String {
    let mut root = crate::Args::command();
    root.build();
    let mut out = String::from(PREAMBLE);
    for sub in root.get_subcommands() {
        render_command(sub, "spora", &mut out);
    }
    out
}

fn render_command(cmd: &clap::Command, parent: &str, out: &mut String) {
    let path = format!("{parent} {}", cmd.get_name());
    out.push_str(&format!("## `{path}`\n\n"));
    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        out.push_str(&format!("{}\n\n", escape_markdown(&about.to_string())));
    }
    out.push_str(&format!(
        "```text\n{}\n```\n\n",
        cmd.clone()
            .render_usage()
            .to_string()
            .trim_start_matches("Usage: ")
            .trim()
    ));
    for arg in cmd.get_positionals() {
        if arg.is_hide_set() {
            continue;
        }
        render_arg(arg, out);
    }
    for arg in cmd.get_arguments() {
        if arg.is_positional()
            || arg.is_hide_set()
            || matches!(arg.get_id().as_str(), "help" | "version")
        {
            continue;
        }
        render_arg(arg, out);
    }
    for sub in cmd.get_subcommands() {
        render_command(sub, &path, out);
    }
}

fn render_arg(arg: &clap::Arg, out: &mut String) {
    let mut name = match arg.get_long() {
        Some(long) => format!("--{long}"),
        None => format!("<{}>", arg.get_id().to_string().to_uppercase()),
    };
    if arg.get_long().is_some() && arg.get_action().takes_values() {
        let values: Vec<String> = arg
            .get_value_names()
            .map(|names| names.iter().map(|n| format!("<{n}>")).collect())
            .unwrap_or_else(|| vec![format!("<{}>", arg.get_id().to_string().to_uppercase())]);
        name = format!("{name} {}", values.join(" "));
    }
    out.push_str(&format!("**`{name}`**"));
    let mut notes = Vec::new();
    if arg.is_required_set() {
        notes.push("required".to_string());
    }
    if matches!(arg.get_action(), clap::ArgAction::Append) {
        notes.push("repeatable".to_string());
    }
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|v| !v.is_empty())
        .collect();
    if !defaults.is_empty() {
        notes.push(format!("default `{}`", defaults.join(", ")));
    }
    if !notes.is_empty() {
        out.push_str(&format!(" *({})*", notes.join(", ")));
    }
    out.push_str("  \n");
    if let Some(help) = arg.get_long_help().or_else(|| arg.get_help()) {
        out.push_str(&format!("{}\n", escape_markdown(&help.to_string())));
    }
    out.push('\n');
}

/// Help text is plain prose to clap but markdown to the book: angle-bracket
/// placeholders like `<routing-key>` would parse as HTML tags. Escape them,
/// except inside backtick code spans, where a backslash would show up
/// literally.
fn escape_markdown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_code = false;
    for c in text.chars() {
        match c {
            '`' => {
                in_code = !in_code;
                out.push(c);
            }
            '<' | '>' if !in_code => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    /// These pages are published on spora.to, so the site's copy guide
    /// applies to them; its hardest rule is machine-checkable: no em dashes,
    /// in any language.
    #[test]
    fn published_pages_follow_the_copy_guide() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs-site/src");
        let mut stack = vec![std::path::PathBuf::from(root)];
        let mut checked = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("docs-site/src exists") {
                let path = entry.expect("read dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "md") {
                    let text = std::fs::read_to_string(&path).expect("read page");
                    assert!(
                        !text.contains('\u{2014}'),
                        "{} contains an em dash; the site copy guide bans them (use a period, comma, or colon)",
                        path.display()
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked > 10, "docs pages went missing ({checked} found)");
    }

    /// The committed command reference must match what the current clap
    /// definitions render. Regenerate with:
    /// `SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference`
    #[test]
    fn cli_reference_is_current() {
        let want = super::render_cli_reference();
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../docs-site/src/reference/cli.md"
        );
        if std::env::var_os("SPORA_UPDATE_DOCS").is_some() {
            std::fs::write(path, &want).expect("write the reference");
            return;
        }
        let have = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            have == want,
            "docs-site/src/reference/cli.md does not match the clap definitions; \
             regenerate it with: SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference"
        );
    }
}
