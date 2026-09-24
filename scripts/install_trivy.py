"""Install the pinned upstream Linux release; verify SHA256 before extraction."""
import hashlib
import io
import platform
import tarfile
import urllib.request
from pathlib import Path

VERSION = '0.74.0'
RELEASES = {
    'x86_64': ('64bit', '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'),
    'aarch64': ('ARM64', 'b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5'),
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
