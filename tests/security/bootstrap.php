<?php
require_once dirname(dirname(__DIR__)) . '/php/autoload.php';

// A real in-memory session store keeps fixtures independent of PHP's session files.
class SecurityTestSession implements elFinderSessionInterface
{
    private $data = array();

    public function start() { return $this; }
    public function close() { return $this; }
    public function get($key, $empty = null) { return isset($this->data[$key]) ? $this->data[$key] : $empty; }
    public function set($key, $data) { $this->data[$key] = $data; return $this; }
    public function remove($key) { unset($this->data[$key]); return $this; }
}

function securityAssert($condition, $message)
{
    if (!$condition) {
        throw new Exception($message);
    }
}

function securityRemoveFixture($path)
{
    if (is_link($path) || is_file($path)) {
        unlink($path);
    } elseif (is_dir($path)) {
        foreach (scandir($path) as $name) {
            if ($name !== '.' && $name !== '..') {
                securityRemoveFixture($path . DIRECTORY_SEPARATOR . $name);
            }
        }
        rmdir($path);
    }
}

function securityHash($volume, $relative)
{
    return $volume->id() . rtrim(strtr(base64_encode($relative), '+/=', '-_.'), '.');
}

function securityRunTests($tests)
{
    $failures = 0;
    foreach ($tests as $name => $test) {
        try {
            $test();
            securityAssert(!str_contains(json_encode(elFinder::$phpErrors), 'DEPRECATED:'), 'PHP deprecations: ' . json_encode(elFinder::$phpErrors));
            echo "PASS " . $name . "\n";
        } catch (Throwable $e) {
            ++$failures;
            echo "FAIL " . $name . ': ' . $e->getMessage() . "\n";
        }
    }
    echo count($tests) . ' tests, ' . $failures . " failures\n";
    return $failures ? 1 : 0;
}
