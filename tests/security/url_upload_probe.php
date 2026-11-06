<?php
// Expose only the URL-upload boundary; no volumes or production session are needed.
require dirname(dirname(__DIR__)) . '/php/elFinder.class.php';

class SecurityUrlUploadProbe extends elFinder
{
    public function __construct($options)
    {
        $this->uploadAllowedLanIpClasses = array_flip(isset($options['lan']) ? $options['lan'] : array());
        if (isset($options['prefix'])) {
            $prefix = $options['prefix'];
            $this->urlUploadFilter = function ($url) use ($prefix) {
                return strpos($url, $prefix) === 0;
            };
        }
    }

    public function validate($url)
    {
        return $this->validate_address($url);
    }

    public function fetch($url, $stream)
    {
        $fp = $stream ? fopen('php://temp', 'w+b') : null;
        $result = $this->get_remote_contents($url, 2, 5, 'elFinder security test', $fp);
        if ($fp) {
            if ($result !== false) {
                rewind($fp);
                $result = stream_get_contents($fp);
            }
            fclose($fp);
        }
        return $result;
    }
}

set_error_handler(function ($severity, $message, $file, $line) {
    throw new ErrorException($message, 0, $severity, $file, $line);
});
$options = json_decode($argv[1], true);
$probe = new SecurityUrlUploadProbe($options);
$result = $options['mode'] === 'validate'
    ? $probe->validate($options['url'])
    : $probe->fetch($options['url'], !empty($options['stream']));
echo json_encode($result);
