<?php
require __DIR__ . '/bootstrap.php';
define('ELFINDER_ZOHO_OFFICE_APIKEY', 'fixture-only-key');

class SecurityZohoEditor extends elFinderEditorZohoOffice
{
    public function issue($hash) { return $this->createCallbackState('save', $hash, $this->getCallbackStateSecret()); }
    public function verify($parameters, $method = 'save', $secret = null)
    {
        return $this->verifyCallbackRequest($method, $parameters, $secret === null ? $this->getCallbackStateSecret() : $secret);
    }
    public function expire($parameters)
    {
        $parameters['expires'] = time() - 1;
        $state = $this->readCallbackState($parameters['token']);
        $state['expires'] = $parameters['expires'];
        $this->writeCallbackState($parameters['token'], $state);
        $parameters['sig'] = $this->createCallbackSignature('save', $parameters['token'], $parameters['expires'], $this->getCallbackStateSecret());
        return $parameters;
    }
    public function consume($token) { $this->consumeCallbackState($token); }
}

$fixture = sys_get_temp_dir() . '/elfinder-callbacks-' . uniqid('', true);
mkdir($fixture);
mkdir($fixture . '/root');
register_shutdown_function('securityRemoveFixture', $fixture);
file_put_contents($fixture . '/root/document.txt', 'original');
file_put_contents($fixture . '/root/readonly.txt', 'readonly sentinel');
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = array('cmd' => 'editor');
$finder = new elFinder(array(
    'session' => new SecurityTestSession(), 'commonTempPath' => $fixture, 'connectionFlagsPath' => $fixture,
    'roots' => array(array('driver' => 'LocalFileSystem', 'path' => $fixture . '/root', 'id' => 'callback', 'tmbPath' => '',
        'uploadDeny' => array('all'), 'uploadAllow' => array('text/plain'), 'uploadOrder' => array('deny', 'allow'),
        'attributes' => array(array('pattern' => '~^/readonly\.txt$~', 'write' => false)))),
));
$volume = $finder->getVolume('lcallback_');
$hash = securityHash($volume, 'document.txt');
$editor = new SecurityZohoEditor($finder, array());
$tests = array();
$tests['signed state is bound to the original document and method'] = function () use ($editor, $hash) {
    $parameters = $editor->issue($hash);
    $parameters['target'] = 'attacker-selected-target';
    securityAssert($editor->verify($parameters)['hash'] === $hash, 'Document binding was replaced');
    securityAssert($editor->verify($parameters, 'different') === false, 'Signature accepted another method');
};
$tests['incorrect signatures and keys cannot authorize a callback'] = function () use ($editor, $hash) {
    $parameters = $editor->issue($hash);
    securityAssert($editor->verify($parameters, 'save', 'incorrect-key') === false, 'Incorrect secret accepted');
    $parameters['sig'] = str_repeat('0', 64);
    securityAssert($editor->verify($parameters) === false, 'Incorrect signature accepted');
};
$tests['an unsigned expired timestamp cannot invalidate a live callback token'] = function () use ($editor, $hash) {
    $parameters = $editor->issue($hash);
    $forged = $parameters;
    $forged['expires'] = '1';
    $forged['sig'] = 'invalid';
    securityAssert($editor->verify($forged) === false, 'Forged callback accepted');
    securityAssert((bool)$editor->verify($parameters), 'Unauthenticated expiry deleted valid callback state');
};
$tests['genuinely expired callback states are rejected'] = function () use ($editor, $hash) {
    securityAssert($editor->verify($editor->expire($editor->issue($hash))) === false, 'Expired callback accepted');
};
$tests['consumed one-shot states cannot be reused'] = function () use ($editor, $hash) {
    $parameters = $editor->issue($hash);
    $editor->consume($parameters['token']);
    securityAssert($editor->verify($parameters) === false, 'Consumed state accepted');
};
$tests['Zoho repeated autosaves remain supported within the signed lifetime'] = function () use ($editor, $hash, $fixture) {
    $parameters = $editor->issue($hash);
    $temporary = $fixture . '/uploaded.txt';
    $_FILES = array('content' => array('tmp_name' => $temporary, 'error' => 0));
    $_POST = $parameters;
    foreach (array('first save', 'second save') as $content) {
        file_put_contents($temporary, $content);
        $result = $editor->save();
        securityAssert($result['header'] === 'HTTP/1.1 200 OK', 'Valid autosave failed');
        securityAssert(file_get_contents($fixture . '/root/document.txt') === $content, 'Autosave content mismatch');
    }
};
$tests['callback save rechecks current document write permissions'] = function () use ($editor, $volume, $fixture) {
    $_POST = $editor->issue(securityHash($volume, 'readonly.txt'));
    file_put_contents($fixture . '/denied.txt', 'replacement');
    $_FILES = array('content' => array('tmp_name' => $fixture . '/denied.txt', 'error' => 0));
    $result = $editor->save();
    securityAssert($result['header'] !== 'HTTP/1.1 200 OK', 'Readonly document was saved');
    securityAssert(file_get_contents($fixture . '/root/readonly.txt') === 'readonly sentinel', 'Readonly sentinel changed');
};
$tests['callback save applies MIME restrictions to replacement content'] = function () use ($editor, $hash, $fixture) {
    $_POST = $editor->issue($hash);
    file_put_contents($fixture . '/payload.txt', '<?php echo "unsafe";');
    $_FILES = array('content' => array('tmp_name' => $fixture . '/payload.txt', 'error' => 0));
    $result = $editor->save();
    securityAssert($result['header'] !== 'HTTP/1.1 200 OK', 'Forbidden callback content was saved');
    securityAssert(file_get_contents($fixture . '/root/document.txt') === 'second save', 'Forbidden callback changed document');
};
exit(securityRunTests($tests));
