<?php
// Run with: rtk php tests/security/test_filesystem.php
require __DIR__ . '/bootstrap.php';

$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = array('cmd' => 'upload');
$fixture = sys_get_temp_dir() . '/elfinder-fs-' . uniqid('', true);
mkdir($fixture);
register_shutdown_function('securityRemoveFixture', $fixture);
$root = $fixture . '/root';
$outside = $fixture . '/outside';
mkdir($root);
mkdir($outside);
mkdir($fixture . '/root-other');
file_put_contents($fixture . '/root-other/sentinel.txt', 'sibling sentinel');
mkdir($root . '/inside');
mkdir($root . '/destination');
foreach (array('upload', 'copy', 'move') as $operation) { mkdir($root . '/destination/' . $operation); }
file_put_contents($root . '/inside/normal.txt', 'inside content');
file_put_contents($root . '/denied.txt', 'source must survive');
foreach (array('tree-copy', 'tree-move') as $tree) {
    mkdir($root . '/' . $tree);
    file_put_contents($root . '/' . $tree . '/guard.txt', 'protected destination');
}
file_put_contents($outside . '/sentinel.txt', 'outside sentinel');
symlink($outside, $root . '/escape');
symlink('../outside', $root . '/relative-escape');
symlink($outside . '/sentinel.txt', $root . '/outside-file.txt');
symlink($root . '/inside', $root . '/internal-link');
symlink($root . '/inside/normal.txt', $root . '/internal-file.txt');

$finder = new elFinder(array(
    'session' => new SecurityTestSession(),
    'connectionFlagsPath' => $fixture,
    'commonTempPath' => $fixture,
    'roots' => array(array(
        'driver' => 'LocalFileSystem', 'path' => $root, 'id' => 'security',
        'tmbPath' => '', 'checkSubfolders' => false,
        'imgLib' => 'gd',
        'attributes' => array(
            array('pattern' => '~^/destination/(?:upload|copy|move)/denied\.txt$~', 'write' => false),
            array('pattern' => '~^/destination/tree-(?:copy|move)/guard\.txt$~', 'write' => false),
        ),
    )),
));
$volume = $finder->getVolume('lsecurity_');
securityAssert($volume !== false, 'Fixture volume must mount');
$rootHash = securityHash($volume, '/');
$tests = array();

$tests['forged absolute and parent paths cannot read a sibling root'] = function () use ($volume, $outside, $fixture) {
    foreach (array($outside . '/sentinel.txt', $fixture . '/root-other/sentinel.txt', '../root-other/sentinel.txt') as $path) {
        securityAssert($volume->file(securityHash($volume, $path)) === false, 'Outside path was visible: ' . $path);
    }
};
$tests['symlinked ancestor cannot disclose an outside file'] = function () use ($volume) {
    foreach (array('escape/sentinel.txt', 'relative-escape/sentinel.txt') as $path) {
        securityAssert($volume->file(securityHash($volume, $path)) === false, 'File outside root was visible through ' . $path);
    }
};
$tests['outside directory symlinks cannot list files'] = function () use ($volume) {
    $result = $volume->scandir(securityHash($volume, 'escape'));
    securityAssert($result === false || !$result, 'Outside directory could be listed');
};
$tests['symlinked ancestor cannot create directories outside the root'] = function () use ($volume, $outside) {
    $result = $volume->mkdir(securityHash($volume, 'escape'), 'injected');
    securityAssert(!is_dir($outside . '/injected'), 'mkdir escaped the root');
    securityAssert($result === false, 'mkdir should fail');
};
$tests['symlinked ancestor cannot rename outside files'] = function () use ($volume, $outside) {
    file_put_contents($outside . '/rename.txt', 'outside');
    $result = $volume->rename(securityHash($volume, 'escape/rename.txt'), 'renamed.txt');
    securityAssert(is_file($outside . '/rename.txt') && !file_exists($outside . '/renamed.txt'), 'rename modified a file outside root');
    securityAssert($result === false, 'rename should fail');
};
$tests['symlinked ancestor cannot upload outside the root'] = function () use ($volume, $outside) {
    $fp = fopen('php://temp', 'w+b');
    fwrite($fp, 'new upload');
    rewind($fp);
    $result = $volume->upload($fp, securityHash($volume, 'escape'), 'uploaded.txt', $outside . '/sentinel.txt');
    if (is_resource($fp)) { fclose($fp); }
    securityAssert(!file_exists($outside . '/uploaded.txt'), 'upload escaped the root');
    securityAssert($result === false, 'upload should fail');
};
$tests['outside file symlinks cannot be opened'] = function () use ($volume) {
    $fp = $volume->open(securityHash($volume, 'outside-file.txt'));
    if (is_resource($fp)) { fclose($fp); }
    securityAssert($fp === false, 'Outside file symlink could be opened');
};
$tests['symlinked ancestor cannot delete outside files'] = function () use ($volume, $outside) {
    file_put_contents($outside . '/delete.txt', 'outside');
    $result = $volume->rm(securityHash($volume, 'escape/delete.txt'));
    securityAssert(is_file($outside . '/delete.txt'), 'Deletion escaped the root');
    securityAssert($result === false, 'Deletion should fail');
};
$tests['paste cannot read from or write to an outside directory symlink'] = function () use ($volume, $root, $outside, $rootHash) {
    $result = $volume->paste($volume, securityHash($volume, 'escape/sentinel.txt'), $rootHash);
    securityAssert(!file_exists($root . '/sentinel.txt') && $result === false, 'Copy read outside root');
    $result = $volume->paste($volume, securityHash($volume, 'inside/normal.txt'), securityHash($volume, 'escape'));
    securityAssert(!file_exists($outside . '/normal.txt') && $result === false, 'Copy wrote outside root');
};
$tests['upload obeys write restrictions for a new destination file'] = function () use ($volume, $root) {
    $fp = fopen('php://temp', 'w+b');
    fwrite($fp, 'upload content');
    rewind($fp);
    $result = $volume->upload($fp, securityHash($volume, 'destination/upload'), 'denied.txt', $root . '/denied.txt');
    if (is_resource($fp)) { fclose($fp); }
    securityAssert(!file_exists($root . '/destination/upload/denied.txt'), 'Upload bypassed destination write policy');
    securityAssert($result === false, 'Denied upload should fail');
};
$tests['same-volume copy obeys destination write restrictions'] = function () use ($volume, $root) {
    $result = $volume->paste($volume, securityHash($volume, 'denied.txt'), securityHash($volume, 'destination/copy'));
    securityAssert(!file_exists($root . '/destination/copy/denied.txt'), 'Copy bypassed destination write policy');
    securityAssert($result === false, 'Denied copy should fail');
};
$tests['same-volume move obeys destination write restrictions without removing the source'] = function () use ($volume, $root) {
    $result = $volume->paste($volume, securityHash($volume, 'denied.txt'), securityHash($volume, 'destination/move'), true);
    securityAssert(is_file($root . '/denied.txt') && !file_exists($root . '/destination/move/denied.txt'), 'Move bypassed destination write policy');
    securityAssert($result === false, 'Denied move should fail');
};
$tests['recursive copy checks permissions before creating any destination'] = function () use ($volume, $root) {
    $result = $volume->paste($volume, securityHash($volume, 'tree-copy'), securityHash($volume, 'destination'));
    securityAssert($result === false && !file_exists($root . '/destination/tree-copy'), 'Recursive copy bypassed destination write policy');
    securityAssert(file_get_contents($root . '/tree-copy/guard.txt') === 'protected destination', 'Copy changed the source');
};
$tests['recursive move checks permissions before changing either tree'] = function () use ($volume, $root) {
    $result = $volume->paste($volume, securityHash($volume, 'tree-move'), securityHash($volume, 'destination'), true);
    securityAssert($result === false && !file_exists($root . '/destination/tree-move'), 'Recursive move bypassed destination write policy');
    securityAssert(file_get_contents($root . '/tree-move/guard.txt') === 'protected destination', 'Move changed the source');
};
$tests['legitimate directory and file symlinks within root remain readable'] = function () use ($volume) {
    foreach (array('internal-link/normal.txt', 'internal-file.txt', 'inside/normal.txt') as $path) {
        $fp = $volume->open(securityHash($volume, $path));
        securityAssert(is_resource($fp), 'Internal file must be readable: ' . $path);
        $content = stream_get_contents($fp);
        fclose($fp);
        securityAssert($content === 'inside content', 'Unexpected internal file content');
    }
};
$tests['ordinary mkdir and rename still work'] = function () use ($volume, $root, $rootHash) {
    securityAssert((bool)$volume->mkdir($rootHash, 'new-dir'), 'Normal mkdir failed');
    securityAssert((bool)$volume->rename(securityHash($volume, 'new-dir'), 'renamed-dir'), 'Normal rename failed');
    securityAssert(is_dir($root . '/renamed-dir'), 'Renamed directory missing');
};
$tests['ordinary upload copy move and deletion still work'] = function () use ($volume, $root, $rootHash) {
    $fp = fopen('php://temp', 'w+b');
    fwrite($fp, 'inside content');
    rewind($fp);
    $result = $volume->upload($fp, $rootHash, 'uploaded.txt', $root . '/inside/normal.txt');
    if (is_resource($fp)) { fclose($fp); }
    securityAssert((bool)$result && file_get_contents($root . '/uploaded.txt') === 'inside content', 'Normal upload failed');
    $result = $volume->paste($volume, securityHash($volume, 'uploaded.txt'), securityHash($volume, 'destination'));
    securityAssert((bool)$result && file_get_contents($root . '/destination/uploaded.txt') === 'inside content', 'Normal copy failed');
    $result = $volume->paste($volume, securityHash($volume, 'destination/uploaded.txt'), securityHash($volume, 'inside'), true);
    securityAssert((bool)$result && !file_exists($root . '/destination/uploaded.txt') && is_file($root . '/inside/uploaded.txt'), 'Normal move failed');
    securityAssert($volume->rm(securityHash($volume, 'inside/uploaded.txt')) && !file_exists($root . '/inside/uploaded.txt'), 'Normal deletion failed');
};
$tests['allowed recursive copy and move preserve directory contents'] = function () use ($volume, $root) {
    $result = $volume->paste($volume, securityHash($volume, 'inside'), securityHash($volume, 'destination'));
    securityAssert((bool)$result && file_get_contents($root . '/destination/inside/normal.txt') === 'inside content', 'Normal recursive copy failed');
    securityAssert(is_file($root . '/inside/normal.txt'), 'Copy removed original directory');
    $result = $volume->paste($volume, securityHash($volume, 'destination/inside'), securityHash($volume, 'renamed-dir'), true);
    securityAssert((bool)$result && !file_exists($root . '/destination/inside'), 'Normal recursive move failed');
    securityAssert(file_get_contents($root . '/renamed-dir/inside/normal.txt') === 'inside content', 'Moved directory content changed');
};
$tests['resize rejects outside images and preserves normal image editing'] = function () use ($volume, $root, $outside) {
    $image = imagecreatetruecolor(8, 8);
    imagepng($image, $outside . '/image.png');
    imagepng($image, $root . '/image.png');
    unset($image);
    $digest = hash_file('sha256', $outside . '/image.png');
    securityAssert($volume->resize(securityHash($volume, 'escape/image.png'), 4, 4, 0, 0) === false, 'Resize escaped root');
    securityAssert(hash_file('sha256', $outside . '/image.png') === $digest, 'Outside image was changed');
    securityAssert((bool)$volume->resize(securityHash($volume, 'image.png'), 4, 4, 0, 0), 'Normal resize failed');
    $size = getimagesize($root . '/image.png');
    securityAssert($size[0] === 4 && $size[1] === 4, 'Wrong resized dimensions');
};
$tests['a root configured through a symlink remains usable'] = function () use ($fixture, $root) {
    symlink($root, $fixture . '/root-alias');
    $finder = new elFinder(array(
        'session' => new SecurityTestSession(), 'commonTempPath' => $fixture, 'connectionFlagsPath' => $fixture,
        'roots' => array(array('driver' => 'LocalFileSystem', 'path' => $fixture . '/root-alias', 'id' => 'alias', 'tmbPath' => '')),
    ));
    $volume = $finder->getVolume('lalias_');
    securityAssert($volume !== false, 'Symlinked root must mount');
    securityAssert($volume->getContents(securityHash($volume, 'inside/normal.txt')) === 'inside content', 'Symlinked root could not read its file');
};

exit(securityRunTests($tests));
