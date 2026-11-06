<?php
// Disposable loopback-only test application. Never deploy this fixture.
$fixture = getenv('ELFINDER_E2E_ROOT');
if (!$fixture || !is_dir($fixture) || !in_array($_SERVER['REMOTE_ADDR'], array('127.0.0.1', '::1'), true)) {
    http_response_code(404);
    exit;
}
$root = dirname(dirname(dirname(__DIR__)));
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path === '/health') { echo 'ok'; exit; }

// Only serve explicit static asset trees, never arbitrary repository PHP files.
if (preg_match('~^/(?:build/(?:full|minimal)/(?:js|css|img|sounds)/|jquery/)~', $path)) {
    $file = realpath($root . $path);
    $extension = $file ? strtolower(pathinfo($file, PATHINFO_EXTENSION)) : '';
    $types = array('js' => 'application/javascript', 'css' => 'text/css', 'png' => 'image/png', 'gif' => 'image/gif', 'svg' => 'image/svg+xml', 'wav' => 'audio/wav');
    if (!$file || strpos($file, $root . DIRECTORY_SEPARATOR) !== 0 || !isset($types[$extension]) || !is_file($file)) {
        http_response_code(404); exit;
    }
    header('Content-Type: ' . $types[$extension]);
    readfile($file);
    exit;
}

session_set_cookie_params(array('secure' => false, 'httponly' => true, 'samesite' => 'Lax'));
session_start();
if ($path === '/login') {
    $_SESSION['fixture_authenticated'] = true;
    header('Content-Type: application/json');
    echo '{"authenticated":true}';
    exit;
}
if (empty($_SESSION['fixture_authenticated'])) { http_response_code(401); echo 'Authentication required'; exit; }

$userDir = $fixture . '/users/' . hash('sha256', session_id());
if (!is_dir($userDir)) {
    mkdir($userDir, 0700);
    mkdir($userDir . '/root');
    mkdir($userDir . '/second');
    file_put_contents($userDir . '/root/hello.txt', 'hello from fixture');
}
if ($path === '/control/expire') {
    if (isset($_SESSION['elFinderCaches']['elfinder.csrf'])) {
        $_SESSION['elFinderCaches']['elfinder.csrf']['expires'] = time() - 1;
    }
    header('Content-Type: application/json'); echo '{"expired":true}'; exit;
}
if ($path === '/control/seed') {
    $names = array('<img src=x onerror=window.__elfinderXss=1>.txt', 'quote" onmouseover="window.__elfinderXss=1.txt');
    foreach ($names as $name) { file_put_contents($userDir . '/root/' . $name, 'untrusted filename'); }
    if (!is_link($userDir . '/root/alias.txt')) { symlink($names[0], $userDir . '/root/alias.txt'); }
    header('Content-Type: application/json'); echo json_encode(array('names' => $names)); exit;
}
if ($path === '/connector') {
    require $root . '/php/autoload.php';
    define('ELFINDER_ZOHO_OFFICE_APIKEY', 'fixture-only-key');
    class elFinderEditorDisabledFixture extends elFinderEditor {
        protected $allowed = array('init');
        public function enabled() { return false; }
        public function init() { return array('disabledPluginExecuted' => true); }
    }
    $roots = array();
    foreach (array('root' => 'e2e', 'second' => 'second') as $directory => $id) {
        $roots[] = array(
            'driver' => 'LocalFileSystem', 'path' => $userDir . '/' . $directory, 'id' => $id,
            'alias' => $directory, 'tmbPath' => '', 'tmpPath' => $fixture . '/tmp',
            'uploadMaxSize' => '64K', 'imgLib' => 'gd', 'checkSubfolders' => false,
            'attributes' => array(array('pattern' => '~(?:^|/)denied\.txt$~', 'write' => false)),
        );
        if ($directory === 'second') {
            $roots[count($roots) - 1]['uploadDeny'] = array('all');
            $roots[count($roots) - 1]['uploadAllow'] = array('text/plain');
            $roots[count($roots) - 1]['uploadOrder'] = array('deny', 'allow');
        }
    }
    $finder = new elFinder(array('roots' => $roots, 'commonTempPath' => $fixture . '/tmp', 'connectionFlagsPath' => $fixture . '/tmp'));
    $connector = new elFinderConnector($finder);
    $connector->run();
    exit;
}
if ($path !== '/') { http_response_code(404); exit; }
$variant = isset($_GET['bundle']) && $_GET['bundle'] === 'minimal' ? 'minimal' : 'full';
$jquery = isset($_GET['jquery']) && $_GET['jquery'] === '4' ? '4.0.0' : '3.7.1';
$stem = $variant === 'minimal' ? 'elfinder-minimal' : 'elfinder';
header('Content-Type: text/html; charset=utf-8');
?>
<!doctype html><html><head><meta charset="utf-8"><title>elFinder security fixture</title>
<link rel="stylesheet" href="/jquery/jquery-ui-1.14.2/jquery-ui.css">
<link rel="stylesheet" href="/build/<?php echo $variant; ?>/css/elfinder.min.css">
<script src="/jquery/jquery-<?php echo $jquery; ?>.js"></script>
<script src="/jquery/jquery-ui-1.14.2/jquery-ui.js"></script>
<script src="/build/<?php echo $variant; ?>/js/<?php echo $stem; ?>.full.js"></script>
</head><body><div id="elfinder"></div><script>
window.__elfinderXss = 0;
window.fm = jQuery('#elfinder').elfinder({
    url: '/connector', lang: 'en', height: 500, sound: true,
    soundPath: '/build/<?php echo $variant; ?>/sounds/',
    baseUrl: '/build/<?php echo $variant; ?>/'
}).elfinder('instance');
</script></body></html>
