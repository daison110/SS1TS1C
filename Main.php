<?php
session_start();

// ログイン状態チェック
if (!isset($_SESSION["NAME"])) {
    header("Location: Logout.php");
    exit;
}
?>

<!doctype html>
<html>
    <head>
        <meta charset="UTF-8">
        <title>メイン</title>
    </head>
    <body>
        <h1>メイン画面</h1>
        
        <ul>
            <li><a href="SignUp.php">新規登録</a></li>
            
            <li><a href="Login.php">ログイン</a></li>
            
            <li><a href="">管理者</a></li>
        </ul>
    </body>
</html>