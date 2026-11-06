<?php
// Run with: rtk php tests/security/test_csrf.php
require __DIR__ . '/bootstrap.php';

class SecurityConnectorResponse extends Exception
{
    public $data;
    public function __construct($data) { $this->data = $data; }
}

class SecurityCapturingConnector extends elFinderConnector
{
    protected function output(array $data)
    {
        // Exercise run() and real command dispatch, replacing only HTTP output/exit.
        throw new SecurityConnectorResponse($data);
    }
}

function securityConnectorRequest($finder, $request, $token = null)
{
    $_SERVER['REQUEST_METHOD'] = 'POST';
    $_GET = array();
    $_POST = $request;
    $_FILES = array();
    unset($_SERVER['HTTP_X_ELFINDER_CSRF']);
    if ($token !== null) { $_SERVER['HTTP_X_ELFINDER_CSRF'] = $token; }
    try {
        $connector = new SecurityCapturingConnector($finder);
        $connector->run();
    } catch (SecurityConnectorResponse $response) {
        return $response->data;
    }
    throw new Exception('Connector did not produce a response');
}

class elFinderEditorCsrfFixture extends elFinderEditor
{
    protected $allowed = array('init', 'save');
    public function init() { return array('executed' => true); }
    public function save() { return array('executed' => true); }
}
class elFinderEditorDisabledCsrfFixture extends elFinderEditorCsrfFixture
{
    public function enabled() { return false; }
}

$fixture = sys_get_temp_dir() . '/elfinder-csrf-' . uniqid('', true);
mkdir($fixture);
mkdir($fixture . '/root');
register_shutdown_function('securityRemoveFixture', $fixture);
$_SERVER['REQUEST_METHOD'] = 'POST';
$session = new SecurityTestSession();
$options = array(
    'session' => $session, 'commonTempPath' => $fixture, 'connectionFlagsPath' => $fixture,
    'roots' => array(array('driver' => 'LocalFileSystem', 'path' => $fixture . '/root', 'id' => 'csrf', 'tmbPath' => '')),
);
$finder = new elFinder($options);
$rootHash = 'lcsrf_Lw';
$initial = securityConnectorRequest($finder, array('cmd' => 'open', 'init' => 1, 'target' => $rootHash));
securityAssert(!isset($initial['error']) && !empty($initial['csrf']), 'Initialization must issue a token');
$token = $initial['csrf'];
$tests = array();

$tests['initialization issues and reuses a session token'] = function () use ($finder, $rootHash, $token) {
    $response = securityConnectorRequest($finder, array('cmd' => 'open', 'init' => 1, 'target' => $rootHash));
    securityAssert($response['csrf'] === $token, 'Unexpired session token should be stable across tabs');
};
$tests['every mutating connector command rejects a missing token'] = function () use ($finder) {
    foreach (array('archive', 'chmod', 'duplicate', 'extract', 'mkdir', 'mkfile', 'netmount', 'paste', 'put', 'rename', 'resize', 'rm', 'upload') as $command) {
        $response = securityConnectorRequest($finder, array('cmd' => $command));
        securityAssert(!empty($response['csrfReload']) && in_array('HTTP/1.1 403 Forbidden', $response['header']), 'Missing CSRF validation for ' . $command);
    }
};
$tests['missing and incorrect tokens cannot create a directory'] = function () use ($finder, $rootHash, $fixture) {
    foreach (array(null, '', 'invalid-token') as $token) {
        $response = securityConnectorRequest($finder, array('cmd' => 'mkdir', 'target' => $rootHash, 'name' => 'forbidden'), $token);
        securityAssert(!empty($response['csrfReload']), 'Expected CSRF rejection');
        securityAssert(!file_exists($fixture . '/root/forbidden'), 'Rejected request changed filesystem');
    }
};
$tests['valid token allows mutation and refreshes expiry'] = function () use ($finder, $rootHash, $fixture, $session, $token) {
    $session->set('elfinder.csrf', array('token' => $token, 'expires' => time() + 30));
    $response = securityConnectorRequest($finder, array('cmd' => 'mkdir', 'target' => $rootHash, 'name' => 'allowed'), $token);
    securityAssert(empty($response['error']) && is_dir($fixture . '/root/allowed'), 'Valid token did not allow mkdir');
    $stored = $session->get('elfinder.csrf');
    securityAssert($stored['expires'] > time() + 800, 'Authenticated mutation did not refresh token expiry');
};
$tests['read-only requests work without a token but cannot extend expiry'] = function () use ($finder, $rootHash, $session, $token) {
    $expires = time() + 30;
    $session->set('elfinder.csrf', array('token' => $token, 'expires' => $expires));
    $response = securityConnectorRequest($finder, array('cmd' => 'open', 'target' => $rootHash));
    securityAssert(empty($response['error']), 'Read-only browse must remain accessible');
    securityAssert($session->get('elfinder.csrf')['expires'] === $expires, 'Read-only request without token extended expiry');
};
$tests['browser editor methods require CSRF including custom save methods'] = function () use ($finder, $token) {
    foreach (array('init', 'save') as $method) {
        $request = array('cmd' => 'editor', 'name' => 'CsrfFixture', 'method' => $method);
        $response = securityConnectorRequest($finder, $request);
        securityAssert(!empty($response['csrfReload']) && empty($response['executed']), 'Editor executed without CSRF');
        $response = securityConnectorRequest($finder, $request, $token);
        securityAssert(!empty($response['executed']), 'Valid browser editor request was rejected');
    }
};
$tests['disabled editors cannot execute even with a valid token'] = function () use ($finder, $token) {
    $response = securityConnectorRequest($finder, array('cmd' => 'editor', 'name' => 'DisabledCsrfFixture', 'method' => 'init'), $token);
    securityAssert(!empty($response['error']) && empty($response['executed']), 'Disabled editor executed');
};
$tests['editor discovery remains available with a valid token'] = function () use ($finder, $token) {
    $response = securityConnectorRequest($finder, array('cmd' => 'editor', 'name' => array('CsrfFixture', 'DisabledCsrfFixture'), 'method' => 'enabled'), $token);
    securityAssert($response['CsrfFixture'] === true && $response['DisabledCsrfFixture'] === false, 'Editor availability is incorrect');
};
$tests['expired token is rejected before mutation and initialization rotates it'] = function () use ($finder, $rootHash, $session, $token, $fixture) {
    $session->set('elfinder.csrf', array('token' => $token, 'expires' => time() - 1));
    $response = securityConnectorRequest($finder, array('cmd' => 'mkdir', 'target' => $rootHash, 'name' => 'expired'), $token);
    securityAssert(!empty($response['csrfReload']) && !file_exists($fixture . '/root/expired'), 'Expired token was accepted');
    $response = securityConnectorRequest($finder, array('cmd' => 'open', 'init' => 1, 'target' => $rootHash));
    securityAssert(!empty($response['csrf']) && $response['csrf'] !== $token, 'Initialization did not rotate expired token');
};
$tests['a token issued to a different session cannot authorize writes'] = function () use ($options, $rootHash, $token, $fixture) {
    $options['session'] = new SecurityTestSession();
    $other = new elFinder($options);
    $response = securityConnectorRequest($other, array('cmd' => 'open', 'init' => 1, 'target' => $rootHash));
    securityAssert($response['csrf'] !== $token, 'Sessions unexpectedly share tokens');
    $response = securityConnectorRequest($other, array('cmd' => 'mkdir', 'target' => $rootHash, 'name' => 'cross-session'), $token);
    securityAssert(!empty($response['csrfReload']) && !file_exists($fixture . '/root/cross-session'), 'Another session token was accepted');
};

exit(securityRunTests($tests));
