<?php
require __DIR__ . '/bootstrap.php';

class SecurityArchiveDriver extends elFinderVolumeLocalFileSystem
{
    public static function unpackZip($file, $directory, $limit)
    {
        self::$maxArcFilesSize = $limit;
        return parent::zipArchiveUnzip($file, $directory);
    }

    public static function unpackForVolume($file, $directory)
    {
        return parent::zipArchiveUnzip($file, $directory);
    }
}

function securityZip($file, $members)
{
    $zip = new ZipArchive();
    securityAssert($zip->open($file, ZipArchive::CREATE | ZipArchive::OVERWRITE) === true, 'Cannot create fixture ZIP');
    foreach ($members as $name => $content) { $zip->addFromString($name, $content); }
    $zip->close();
}

$fixture = sys_get_temp_dir() . '/elfinder-archives-' . uniqid('', true);
mkdir($fixture);
register_shutdown_function('securityRemoveFixture', $fixture);
securityZip($fixture . '/small.zip', array('document.txt' => 'archive content'));
securityZip($fixture . '/large.zip', array('large.txt' => str_repeat('A', 4096)));
securityZip($fixture . '/traversal.zip', array('../sentinel.txt' => 'changed', '/absolute.txt' => 'bad'));
file_put_contents($fixture . '/sentinel.txt', 'outside sentinel');
$tests = array();
$tests['ZIP below the configured decompression limit extracts normally'] = function () use ($fixture) {
    mkdir($fixture . '/normal');
    securityAssert(SecurityArchiveDriver::unpackZip($fixture . '/small.zip', $fixture . '/normal', 100), 'Valid ZIP failed');
    securityAssert(file_get_contents($fixture . '/normal/document.txt') === 'archive content', 'Wrong ZIP contents');
};
$tests['ZIP exceeding the limit is rejected before creating extracted files'] = function () use ($fixture) {
    mkdir($fixture . '/limited');
    $rejected = false;
    try { SecurityArchiveDriver::unpackZip($fixture . '/large.zip', $fixture . '/limited', 100); }
    catch (Exception $e) { $rejected = ($e->getMessage() === elFinder::ERROR_ARC_MAXSIZE); }
    securityAssert($rejected, 'Oversized ZIP was not rejected before extraction');
    securityAssert(count(scandir($fixture . '/limited')) === 2, 'ZIP wrote files before rejecting the size');
};
$tests['zero decompression limit retains documented unlimited extraction'] = function () use ($fixture) {
    mkdir($fixture . '/unlimited');
    securityAssert(SecurityArchiveDriver::unpackZip($fixture . '/small.zip', $fixture . '/unlimited', 0), 'Unlimited ZIP extraction failed');
    securityAssert(is_file($fixture . '/unlimited/document.txt'), 'Unlimited extraction produced no file');
};
$tests['archive member paths cannot overwrite an external sentinel'] = function () use ($fixture) {
    mkdir($fixture . '/paths');
    SecurityArchiveDriver::unpackZip($fixture . '/traversal.zip', $fixture . '/paths', 100);
    securityAssert(file_get_contents($fixture . '/sentinel.txt') === 'outside sentinel', 'ZIP escaped extraction directory');
};

$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = array('cmd' => 'extract');
mkdir($fixture . '/volume');
securityZip($fixture . '/volume/mixed.zip', array('allowed.txt' => 'plain text', 'payload.php' => '<?php echo "unsafe";', '.hidden' => 'hidden'));
$finder = new elFinder(array(
    'session' => new SecurityTestSession(), 'commonTempPath' => $fixture, 'connectionFlagsPath' => $fixture,
    'roots' => array(array(
        'driver' => 'LocalFileSystem', 'path' => $fixture . '/volume', 'id' => 'archives', 'tmbPath' => '',
        'uploadDeny' => array('all'), 'uploadAllow' => array('text/plain', 'application/zip'), 'uploadOrder' => array('deny', 'allow'),
        'archivers' => array('extract' => array('application/zip' => array('cmd' => 'phpfunction', 'argc' => array('SecurityArchiveDriver', 'unpackForVolume'), 'ext' => 'zip'))),
    )),
));
// Use the production extraction callback directly; the public volume tests also
// exercise quarantine, name and MIME validation after unpacking.
$volume = $finder->getVolume('larchives_');
$tests['quarantine preserves allowed files and filters forbidden MIME and names'] = function () use ($volume, $fixture) {
    $result = $volume->extract(securityHash($volume, 'mixed.zip'), true);
    securityAssert((bool)$result, 'ZIP quarantine extraction failed');
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($fixture . '/volume', FilesystemIterator::SKIP_DOTS));
    $names = array();
    foreach ($files as $file) { $names[] = $file->getFilename(); }
    securityAssert(in_array('allowed.txt', $names), 'Allowed file was not extracted');
    securityAssert(!in_array('payload.php', $names) && !in_array('.hidden', $names), 'Forbidden archive entry was published');
};

exit(securityRunTests($tests));
