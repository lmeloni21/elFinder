"""Run PHP 8.5 regression suites, failing on the first failed subprocess."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
php = os.environ.get('PHP_BINARY', 'php')
subprocess.run([php, '-r', 'exit(PHP_VERSION_ID >= 80500 ? 0 : 1);'], check=True)
sources = list((ROOT / 'php').rglob('*.php')) + list((ROOT / 'php').glob('*.php-dist'))
sources += list((ROOT / 'util').glob('*.php')) + list((ROOT / 'tests').rglob('*.php'))
for source in sources:
    result = subprocess.run([php, '-d', 'xdebug.mode=off', '-l', str(source)],
                            capture_output=True, text=True)
    if result.returncode or 'Deprecated' in result.stdout + result.stderr:
        sys.exit(result.stdout + result.stderr)
print(f'PASS PHP syntax and compile-time deprecation checks: {len(sources)} files', flush=True)
for suite in ['php85', 'filesystem', 'csrf', 'archives', 'callbacks']:
    subprocess.run([php, '-d', 'xdebug.mode=off', '-d', 'error_reporting=32767',
                    str(ROOT / 'tests/security' / ('test_' + suite + '.php'))], check=True)
for suite in ['url_upload', 'mysql']:
    subprocess.run([sys.executable, str(ROOT / 'tests/security' / ('test_' + suite + '.py'))],
                   env=dict(os.environ, PHP_BINARY=php), check=True)
