<?php

$db = new PDO('sqlite:'.dirname(__FILE__).'/db.sqlite');
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->query(
    "CREATE TABLE IF NOT EXISTS users (
       id            INTEGER         PRIMARY KEY AUTOINCREMENT,
       login         TEXT UNIQUE,
       password      TEXT,
       is_admin      INTEGER
    )");
$db->query(
    "CREATE TABLE IF NOT EXISTS sessions (
       id            INTEGER         PRIMARY KEY AUTOINCREMENT,
       created       DATETIME,
       user_id       INTEGER
    )");
$db->query(
    "CREATE TABLE IF NOT EXISTS articles (
       id            INTEGER         PRIMARY KEY AUTOINCREMENT,
       title         TEXT,
       body          TEXT
    )");

$db->query('INSERT OR IGNORE INTO users (login, password, is_admin) VALUES ("admin", "admin123", 1)');


if (!empty($_COOKIE['session_id'])) {
    $session_id = $_COOKIE['session_id'];
}
else {
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        list($login, $password) = explode(':', base64_decode(substr($_SERVER['HTTP_AUTHORIZATION'], strlen("Basic "))));
        $user = $db->query(sprintf('SELECT id, is_admin FROM users WHERE login = "%s" AND password = "%s"', $login, $password))->fetch();
    }
    $db->query(sprintf("INSERT INTO sessions (created, user_id) VALUES ('%s', '%s')",
                       date("Y-m-d H:i:s"),
                       $user['id']));
    $session_id = $db->lastInsertId();
}

$session = $db->query(sprintf(
    "SELECT * from sessions LEFT JOIN users ON users.id = sessions.user_id WHERE sessions.id = %s",
    $session_id))->fetch();

if ($_GET['page'] == 'users')
{
    if ($_SERVER['REQUEST_METHOD'] == 'PUT' ||
        $_SERVER['REQUEST_METHOD'] == 'POST' ||
        $_SERVER['REQUEST_METHOD'] == 'GET')
    {
        if (!$session['is_admin'])
        {
            header('HTTP/1.0 401 Unauthorized');
            header('WWW-Authenticate: Basic realm="Admin Zone');
            die();
        }
    }
    if ($_SERVER['REQUEST_METHOD'] == 'PUT')
    {
        $db->query(sprintf('UPDATE users SET password = "%s" WHERE id = "%s"',
                           $_GET['new_password'], $_GET['user_id']));
    }
    if ($_SERVER['REQUEST_METHOD'] == 'POST')
    {
        $db->query(sprintf('INSERT INTO users (login, password, is_admin) VALUES ("%s", "%s", 0)',
                           $_GET['login'], $_GET['password']));
    }
    // Que ce soit un GET, PUT, ou POST on affiche la liste:
    // TODO: tpl, en attendant, var_dump ça suffit, c'est une page d'admin.
    var_dump($db->query('SELECT * FROM users')->fetchAll());
}


if ($_GET['page'] == 'sessions') {
    if (!$session['is_admin'])
    {
        header('HTTP/1.0 401 Unauthorized');
        header('WWW-Authenticate: Basic realm="Admin Zone"');
        die();
    }
    var_dump($db->query('SELECT * FROM sessions')->fetchall());
}

if ($_GET['page'] == 'redirect') {
    /**
     * Do not allow open redirects, only signed redirects.  Open redirects
     * allow easy phishing (presenting pretty URLs with legit domain,
     * redirecting to phising site.
     */
    $target = $_GET['target'];
    $given_checksum = $_GET['checksum'];
    if (sha1($target) != $given_checksum)
    {
        header('HTTP/1.0 400 Bad request');
        die();
    }
    header("Location: " . $_GET['target'], TRUE, 301);
    die();
}


if ($_GET['page'] == 'static') {
    /**
     * Allow static assets to be included. Only from ./static/.  We're using
     * PHP even for static assets so we can later minify CSS and JS on the fly
     * \o/
     */
    include "./static/" . $_GET['asset'];
}


if ($_GET['page'] == 'upload') {
    if (!isset($_FILES['file'])) {
        echo '<form method="post" enctype="multipart/form-data">
              <input type="file" name="file">
          <input type="submit" value="upload">
        </form>';
        die();
    }
    $uploaddir = './uploads';
    @mkdir("./uploads", 0700);
    $uploadfile = $uploaddir . '/' . basename($_FILES['file']['name']);
    assert('!in_array("' . $_FILES["file"]["type"] . '", ["image/jpeg", "image/png"])');
    if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
        echo "Uploaded successfully: <a href='$uploadfile'>$uploadfile</a>\n";
        die();
    }
}


if ($_GET['page'] == 'new_article') {
    /**
     * We hired a remote dev to do the client. Note for later: Don't fscking
     * do that ever again.  He did everything in Python (Like PHP was not the
     * obvious choice? (spoiler: he won't get paid)) And he insisted on
     * transmiting everything as base64 encoded "pickled" values, telling
     * that's better than json and easier than protobuf, srly? Fsck this.
     * Plus I hate Python documentation, there's never A SINGLE FSCKING
     * EXAMPLE in this FSCKING DOC.  Hopefully I found an example on
     * stackoverflow, thanks Google for ranking SO before python, but sorry
     * for the code.  TODO: Rewrite the client in PHP.
     *
     * Test data:
     * gAN9cQAoWAQAAABib2R5cQFYFgAAAERvbG9yLCBtdWNoIG11Y2ggZG9sb3JxAlgFAAAAdGl0bGVxA1gLAAAATG9yZW0gSXBzdW1xBHUu
     */

    $base64_encode_picke = $_GET['article'];
    exec(sprintf('python3 -c "import json; import pickle; import base64; print(json.dumps(pickle.loads(base64.b64decode(%s))))"',
                 "'" + $base64_encode_picke + "'"), $output);
    $json = json_decode($output[0], TRUE);
    $db->query(sprintf('INSERT INTO articles (title, body) VALUES ("%s", "%s")',
                       $json['title'], $json['body']));
}

if ($_GET['page'] == 'articles') {
    // TODO: Template.
    var_dump($db->query('SELECT * FROM articles')->fetchall());
}


setcookie('session_id', $session_id);