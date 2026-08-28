# Spora CLI documentation

The book published at https://spora.to/docs/. Markdown lives here; the
website's deploy builds it with [mdBook](https://rust-lang.github.io/mdBook/)
(pinned in `.github/workflows/tests.yml` and in spora-web's playbook) and
serves the output as static files.

## Working on it

```bash
cargo install mdbook --locked --version 0.5.4
mdbook serve docs-site        # live preview at http://localhost:3000
```

## Rules

- `src/reference/cli.md` is GENERATED from the clap definitions. Do not edit
  it by hand: change the doc comments in `spora-cli/src/main.rs`, then run
  `SPORA_UPDATE_DOCS=1 cargo test -p spora-cli cli_reference` to regenerate.
  A test fails while the committed file is stale.
- These pages are published on spora.to, so the website's `COPY_GUIDE.md`
  applies: plain and honest wording, concrete scenarios, and never an em
  dash (use periods, commas, or colons instead).
- New pages must be listed in `src/SUMMARY.md` or mdBook will not build them.
