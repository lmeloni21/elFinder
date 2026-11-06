const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const root = path.resolve(__dirname, '../../..');
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'elfinder-e2e-'));
for (const name of ['sessions', 'tmp', 'users']) fs.mkdirSync(path.join(fixture, name));
const port = process.env.ELFINDER_E2E_PORT || '30871';
const child = spawn(process.env.PHP_BINARY || 'php', [
  '-d', 'xdebug.mode=off', '-d', `session.save_path=${path.join(fixture, 'sessions')}`,
  '-d', 'display_errors=0', '-S', `127.0.0.1:${port}`, path.join(__dirname, 'router.php')
], { cwd: root, env: { ...process.env, ELFINDER_E2E_ROOT: fixture }, stdio: ['ignore', 'ignore', 'pipe'] });
child.stderr.on('data', chunk => {
  const text = chunk.toString();
  if (/Fatal|Warning|Error:/.test(text)) process.stderr.write(text);
});
let stopping = false;
function stop() { if (!stopping) { stopping = true; child.kill('SIGTERM'); } }
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
child.on('exit', code => {
  fs.rmSync(fixture, { recursive: true, force: true });
  process.exit(stopping ? 0 : (code || 1));
});
