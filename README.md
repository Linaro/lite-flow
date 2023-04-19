# LITE Flow tool

This project is an attempt at a reference implementation of the cryptographic
"flow" demonstrating how data undergoes encryption and signing from an embedded
device to the cloud.

In order to gather some meaningful benchmarks, there is also a main program that
is able to run on some embedded targets to benchmark this encryption.

## Submodules

This repo currently brings in a current version of embassy with git submodules,
and if you didn't add `--submodules` when cloning the repo, you will need to
update those:

```
$ git submodule update --init
```

## On target benchmarking

Currently, the benchmark can be run on the STM32F407VGTx Discovery board, which
is available at the time of writing.  This tool needs a rust unstable version,
which can be downloaded with rustup.  It is highly recommended to use rustup to
build this software, as the necessary tools will be automatically installed.

```
$ cd boards/stm32f4-disco
$ cargo build --release
```

Although the rust embedded book describes using openocd to connect to the
target, the `probe-run` tool, built on `probe-rs` provides a much more concise
solution to running and developing on these boards.  It supports the RTT
protocol, and will automatically show available messages as they are printed by
the device.

```
$ cargo install probe-run
```

You should be able to query your probe with:

```
$ probe-run --list-probes
the following probes were found:
[0]: STLink V3 (VID: 0483, PID: 374e, Serial: 001F00094741500420383733, StLink)
```

If the board doesn't show up here, it likely has to do with device permissions
and such.  The [probe-run](https://ferrous-systems.com/blog/probe-run/)
documentation may be helpful in diagnosing problems.

Once that works, you can just issue

```
$ cargo run --release
```

to run the test, and print out messages.  There is a script `./run.sh` in this
directory that uses a grep command to filter out the line information on the log
messages, making the content of the messages easier to read.
