<?php
require __DIR__ . '/bootstrap.php';
$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = array('cmd' => 'open', 'init' => 1);
$socket = getenv('ELFINDER_MYSQL_SOCKET');
securityAssert((bool)$socket, 'Use test_mysql.py to create an isolated database');
$db = new mysqli('localhost', 'fixture', 'fixture-only', 'elfinder_audit', null, $socket);
$db->query("INSERT INTO elfinder_file (id,parent_id,name,content,size,mtime,mime) VALUES (2,1,'allowed-root','',0,1,'directory'), (3,2,'allowed.txt','allowed',7,1,'text/plain'), (4,1,'other-root','',0,1,'directory'), (5,4,'private.txt','PRIVATE',7,1,'text/plain')");
$temporary = sys_get_temp_dir() . '/elfinder-sql-' . uniqid('', true);
mkdir($temporary);
register_shutdown_function('securityRemoveFixture', $temporary);
$finder = new elFinder(array(
    'session' => new SecurityTestSession(), 'commonTempPath' => $temporary, 'connectionFlagsPath' => $temporary,
    'roots' => array(array('driver' => 'MySQL', 'path' => '2', 'id' => 'audit', 'host' => 'localhost',
        'user' => 'fixture', 'pass' => 'fixture-only', 'db' => 'elfinder_audit', 'socket' => $socket, 'tmbPath' => '')),
));
$volume = $finder->getVolume('maudit_');
securityAssert($volume !== false, 'MySQL volume must mount: ' . json_encode($finder->mountErrors));
$tests = array();
$tests['MySQL root and its child remain accessible'] = function () use ($volume) {
    securityAssert((bool)$volume->dir(securityHash($volume, '2')), 'Root not accessible');
    securityAssert($volume->getContents(securityHash($volume, '3')) === 'allowed', 'In-root content not readable');
};
$tests['numeric forged hashes cannot disclose an object outside the configured root'] = function () use ($volume) {
    securityAssert($volume->file(securityHash($volume, '5')) === false, 'Outside object metadata was disclosed');
    securityAssert($volume->getContents(securityHash($volume, '5')) === false, 'Outside content was disclosed');
};
$tests['outside objects cannot be renamed or deleted'] = function () use ($volume, $db) {
    securityAssert($volume->rename(securityHash($volume, '5'), 'changed.txt') === false, 'Outside object was renamed');
    securityAssert($volume->rm(securityHash($volume, '5')) === false, 'Outside object was deleted');
    $row = $db->query('SELECT name,content FROM elfinder_file WHERE id=5')->fetch_assoc();
    securityAssert($row['name'] === 'private.txt' && $row['content'] === 'PRIVATE', 'Outside sentinel changed');
};
$tests['SQL metacharacters in hashes are rejected without modifying data'] = function () use ($volume, $db) {
    foreach (array('3 OR 1=1', '3 UNION SELECT 1', '3;DROP TABLE elfinder_file', '-1', '1e1') as $id) {
        securityAssert($volume->file(securityHash($volume, $id)) === false, 'Non-numeric id accepted');
    }
    securityAssert((int)$db->query('SELECT count(*) AS n FROM elfinder_file')->fetch_assoc()['n'] === 5, 'SQL input changed fixture data');
};
$tests['ordinary in-root mkdir and quoted filenames still work'] = function () use ($volume) {
    $directory = $volume->mkdir(securityHash($volume, '2'), "folder's name");
    securityAssert((bool)$directory && $directory['mime'] === 'directory', 'Quoted mkdir failed');
    securityAssert((bool)$volume->rename($directory['hash'], 'renamed'), 'In-root rename failed');
};
exit(securityRunTests($tests));
