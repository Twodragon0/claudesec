#!/usr/bin/env python3
"""Run a command with stdin connected to a pty slave (makes [[ -t 0 ]] true).

Usage: python3 pty_run.py <cmd> [args...]

Used by the kcov loop in lint.yml to instrument bash functions that have a
[[ ! -t 0 ]] TTY guard (e.g. aws_sso_ensure_login). kcov ptrace-attaches to
the child process it forks; forwarding stdin=pty-slave before exec lets kcov
fork bash with a real terminal on fd 0, so [[ -t 0 ]] returns true inside
those functions.
"""
import os
import pty
import select
import sys


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: pty_run.py cmd [args...]")

    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0:
        os.close(master)
        os.dup2(slave, 0)   # stdin → pty slave
        os.close(slave)
        os.execvp(sys.argv[1], sys.argv[1:])
        os._exit(127)

    os.close(slave)
    try:
        while True:
            r, _, _ = select.select([master], [], [], 120.0)
            if not r:
                break  # 2-min safety timeout
            try:
                data = os.read(master, 4096)
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except OSError:
                break  # EIO when all slave ends are closed (child exited)
    finally:
        try:
            os.close(master)
        except OSError:
            pass

    _, status = os.waitpid(pid, 0)
    sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)


if __name__ == "__main__":
    main()
