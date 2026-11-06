"""Run MySQL driver tests against a disposable MariaDB with no TCP listener."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]

with tempfile.TemporaryDirectory(prefix='elfinder-mysql-') as temporary:
    directory = Path(temporary)
    data = directory / 'data'
    installed = subprocess.run(
        ['mariadb-install-db', '--no-defaults', '--datadir=' + str(data),
         '--auth-root-authentication-method=normal', '--skip-test-db'],
        capture_output=True, text=True, timeout=45,
    )
    if installed.returncode:
        sys.exit(installed.stderr or installed.stdout)
    socket = directory / 'mysql.sock'
    process = subprocess.Popen(
        ['mariadbd', '--no-defaults', '--datadir=' + str(data), '--socket=' + str(socket),
         '--skip-networking', '--pid-file=' + str(directory / 'mysql.pid'),
         '--log-error=' + str(directory / 'mysql.log'), '--innodb-buffer-pool-size=32M',
         '--skip-log-bin', '--max-connections=10'],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        client = ['mysql', '--no-defaults', '--socket=' + str(socket), '-uroot']
        for _ in range(100):
            if process.poll() is not None:
                sys.exit((directory / 'mysql.log').read_text())
            if socket.exists() and subprocess.run(client + ['-e', 'SELECT 1'], capture_output=True).returncode == 0:
                break
            time.sleep(0.1)
        else:
            sys.exit('Disposable MariaDB did not start')
        sql = "CREATE DATABASE elfinder_audit; CREATE USER 'fixture'@'localhost' IDENTIFIED BY 'fixture-only'; GRANT ALL ON elfinder_audit.* TO 'fixture'@'localhost'; USE elfinder_audit;\n"
        sql += (ROOT / 'php/MySQLStorage.sql').read_text()
        subprocess.run(client, input=sql, text=True, check=True, capture_output=True)
        env = dict(os.environ, ELFINDER_MYSQL_SOCKET=str(socket))
        result = subprocess.run([os.environ.get('PHP_BINARY', 'php'), '-d', 'xdebug.mode=off', str(Path(__file__).with_suffix('.php'))], env=env, timeout=30)
        result_code = result.returncode
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
    sys.exit(result_code)
