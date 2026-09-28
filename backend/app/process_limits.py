"""Trusted exec launcher. Avoid preexec_fn in the multithreaded worker."""
import os
import resource
import sys


def main():
    seconds = int(sys.argv[1])
    if not 1 <= seconds <= 1800 or len(sys.argv) < 3:
        raise SystemExit(64)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    cap = min(1024, hard) if hard != resource.RLIM_INFINITY else 1024
    resource.setrlimit(resource.RLIMIT_NOFILE, (cap, cap))
    os.execvpe(sys.argv[2], sys.argv[2:], os.environ)


if __name__ == '__main__':
    main()
