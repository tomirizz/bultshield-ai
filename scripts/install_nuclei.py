"""Pinned official release; extract only the verified executable."""
import hashlib
import io
import platform
import urllib.request
import zipfile
from pathlib import Path

VERSION = '3.11.1'
RELEASES = {
    'x86_64': ('amd64', 'ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6'),
    'aarch64': ('arm64', '8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07'),
}


def main():
    arch, checksum = RELEASES[platform.machine()]
    url = f'https://github.com/projectdiscovery/nuclei/releases/download/v{VERSION}/nuclei_{VERSION}_linux_{arch}.zip'
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(150 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != checksum:
        raise SystemExit('Nuclei checksum mismatch')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        target = Path('/usr/local/bin/nuclei')
        target.write_bytes(archive.read('nuclei'))
        target.chmod(0o755)


if __name__ == '__main__':
    main()
