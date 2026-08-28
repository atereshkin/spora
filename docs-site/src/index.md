# Introduction

Spora is a peer-to-peer VPN. One person shares their Internet connection,
another connects to it through a link. Traffic comes out at the sharer's
home connection, from a real residential IP, which makes it very hard to
tell apart from the sharer's own browsing.

This book covers the **command-line client**, `spora`. It is the same
networking core that powers the Spora apps, driven from a terminal. You can
use it to:

- **share** your connection with someone you trust, and keep a local log of
  what your connection was used for;
- **connect** through a friend's shared connection, as a full VPN client on
  Linux, macOS, or Windows;
- run pieces of your own infrastructure, such as a relay, when you do not
  want to depend on the built-in one;
- automate any of the above: the CLI has a machine-readable mode designed
  for scripts and tests.

If you just want the two-command version, start with the
[Quickstart](quickstart.md). The how-to guides walk through real setups, and
the reference section describes every flag, event, and file.

A note on trust: the person who shares carries the traffic of the person who
connects. Share with people you know, and connect through people who know
you. The [sharing guide](howto/share.md) explains the connection log that
protects the sharer's side of that bargain.
