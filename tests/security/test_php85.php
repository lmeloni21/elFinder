<?php
require __DIR__ . '/bootstrap.php';

securityAssert(PHP_VERSION_ID >= 80500, 'This migration suite requires PHP 8.5+');
error_reporting(E_ALL);
class SecurityExtensibleBoxDriver extends elFinderVolumeBox
{
    protected function _extract($path, $arc) { return 'custom extraction'; }
    public function extractForTest() { return $this->_extract('', []); }
}
$tests = [];
$tests['remote driver operations can still be implemented by subclasses'] = function () {
    securityAssert((new SecurityExtensibleBoxDriver())->extractForTest() === 'custom extraction', 'Driver extension contract changed');
};
$tests['bundled drivers and plugins load and construct on PHP 8.5 without deprecations'] = function () {
    set_error_handler(function ($level, $message, $file, $line) {
        throw new ErrorException($message, 0, $level, $file, $line);
    });
    try {
        foreach (['LocalFileSystem', 'MySQL', 'Trash', 'TrashMySQL', 'FTP', 'SFTPphpseclib', 'Dropbox2', 'GoogleDrive', 'Box', 'OneDrive', 'Group'] as $driver) {
            $class = 'elFinderVolume' . $driver;
            securityAssert(new $class() instanceof elFinderVolumeDriver, 'Cannot construct ' . $class);
        }
        foreach (['AutoResize', 'AutoRotate', 'Normalizer', 'Sanitizer', 'Watermark', 'WinRemoveTailDots'] as $plugin) {
            $class = 'elFinderPlugin' . $plugin;
            securityAssert(class_exists($class), 'Cannot load ' . $class);
        }
    } finally {
        restore_error_handler();
    }
};
$tests['encoding conversion preserves Latin-1 data on PHP 8.5'] = function () {
    // This path previously used the removed/deprecated utf8_encode fallback.
    $finder = (new ReflectionClass(elFinder::class))->newInstanceWithoutConstructor();
    securityAssert($finder->utf8Encode("caf\xe9") === "caf\xc3\xa9", 'Latin-1 conversion changed');
};

exit(securityRunTests($tests));
