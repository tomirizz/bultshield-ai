"""Install the pinned upstream Linux release; verify SHA256 before extraction."""
import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

VERSION = '0.76.0'
RELEASES = {
    'x86_64': ('64bit', 'e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7'),
    'aarch64': ('ARM64', 'aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c'),
}


def main():
    arch, expected = RELEASES[platform.machine()]
    url = f'https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_Linux-{arch}.tar.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        archive = response.read(150 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != expected:
        raise SystemExit('Trivy SHA256 mismatch')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as package:
        binary = package.extractfile('trivy')
        if binary is None:
            raise SystemExit('Trivy binary missing')
        destination = Path('/usr/local/bin/trivy')
        destination.write_bytes(binary.read())
        destination.chmod(0o755)


if __name__ == '__main__':
    main()
