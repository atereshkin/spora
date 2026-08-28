# Files and directories

The CLI follows the XDG conventions on Linux and macOS and the profile
directories on Windows. Overriding environment variables (`XDG_CONFIG_HOME`,
`XDG_STATE_HOME`) are honored.

| what | Linux and macOS | Windows |
|---|---|---|
| Identity (key material behind the share URL) | `~/.config/spora/identity.bin` | `%APPDATA%\spora\identity.bin` |
| Connection log (per share identity) | `~/.local/state/spora/connlog/<routing-key>/` | `%LOCALAPPDATA%\spora\connlog\<routing-key>\` |
| Diagnostic records | `~/.local/state/spora/records/` | `%LOCALAPPDATA%\spora\records\` |

Notes:

- The identity file is the secret behind a stable share URL: mode `0600`,
  written atomically. Copy it to move a share; delete it (or use
  `--fresh`) to revoke the URL. `--identity-file` selects another path.
- The connection log is SQLite; read it with `spora log`, not by hand, and
  note that deleting the identity does not delete the log. It is your
  record of what your connection was used for, and it outlives the URL on
  purpose.
- Records are plain JSON Lines, one file per run; `--record-dir` moves
  them and `--no-record` disables them.
- `spora use` in VPN mode also keeps small runtime files (an instance
  lock, resolver backups) under `/run/spora/` on Linux and
  `/var/db/spora/` on macOS; they are cleaned up automatically.
- On Windows, `spora use` expects `wintun.dll` next to `spora.exe`.
