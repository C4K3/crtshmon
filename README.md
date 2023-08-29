crtshmon is a simple tool that does exactly one thing: Fetch
[CT](https://en.wikipedia.org/wiki/Certificate_Transparency) logs for one or
more websites from [crt.sh](https://crt.sh/), and display information about
certificates not yet seen.

Because crtshmon relies on crt.sh rather than using the upstream CT firehose,
it is fast and lightweight.

# Installation

crtshmon can be used with docker or compatible equivalents:
```
docker run registry.hub.docker.com/c4k3/crtshmon:latest -d example.com
```
It can be installed with cargo:
```
cargo install crtshmon
```
It can also be built from source using cargo:
```
cargo build --release
```
In this case the output will be put into `target/release/crtshmon`.

# Usage

crtshmon will check the domains specified with `--domain`, write information
about newly seen certificates to stdout, and then exit. There is no daemon mode
available.

crtshmon will show only certificates [it hasn't seen yet](#--directory). It
will only show certificates that are not expired.

crtshmon is well-suited for running as a cronjob. If your cron daemon supports
sending the output of jobs by email, you can have notifications about new
certificates delivered by email. If there are no new certificates crtshmon will
exit without writing anything to stdout, meaning you will only be notified when
certificates have been issued (assuming your cron daemon skips notifications
jobs with no output.)

There is no reason to run crtshmon too frequently (more frequently than hourly,
for example.) Inclusion of new certificates into the CT logs is far from
instant.

The following options are available:

## `--domain`

Specify domains you want to check for with `-d`/`--domain`. This option can be repeated multiple times.

## `--directory`

crtshmon will only show a certificate once. To track which certificates it has
seen, it will write a state file. By default the state file is written to
`./crtshmon.json`. The directory it is written to (but not the filename) can be
changed with the `--directory` option.

If run inside docker/kubernetes you will want to mount a persistent volume into
the container for crtshmon to write its state to. You can mount this directory
to `/home/crtshmon`, in which case you won't have to specify any `--directory`.

## `--json-log`

By default crtshmon will output certificate information in a human-readable
plaintext format. It can also output information in ndjson format with the
`--json-log` option.
