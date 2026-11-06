const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const cli = require.resolve('jake/bin/cli.js');

for (const variant of ['full', 'minimal']) {
  const directory = path.join(root, 'build', variant);
  fs.mkdirSync(directory, { recursive: true });
  const task = variant === 'full' ? 'elfinder' : 'elfinder-minimal';
  const result = spawnSync(process.execPath, [cli, '-f', path.join(root, 'Jakefile.js'), '-C', directory, task], { encoding: 'utf8' });
  fs.writeFileSync(path.join(root, 'build', `${variant}.log`), (result.stdout || '') + (result.stderr || ''));
  if (result.status !== 0) {
    process.stderr.write((result.stdout || '').slice(-6000) + (result.stderr || ''));
    process.exit(result.status || 1);
  }
  const stem = variant === 'full' ? 'elfinder' : 'elfinder-minimal';
  for (const suffix of ['full', 'min']) {
    const file = path.join(directory, 'js', `${stem}.${suffix}.js`);
    const source = fs.readFileSync(file, 'utf8');
    if (source.length < 1000 || source.includes('undefined\n')) throw new Error(`Invalid build: ${file}`);
    new vm.Script(source, { filename: file });
  }
  for (const file of ['php/elFinder.class.php', 'php/elFinderConnector.class.php', 'SECURITY_INTEGRATION.md', 'PHP85_MIGRATION.md']) {
    if (!fs.existsSync(path.join(directory, file))) throw new Error(`Missing distribution file: ${file}`);
  }
  console.log(`PASS ${variant} build, full/minified JavaScript syntax and required distribution files`);
}
