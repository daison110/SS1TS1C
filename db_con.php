<?php

// 変数の初期化
$sql = null;
$res = null;
$dbh = null;

try {
	// DBへ接続
	$dbh = new PDO("mysql:host=127.0.0.1; dbname=loginManagement; charset=utf8", 'hogeUser', 'hogehoge');

	// SQL作成
	$sql = "SELECT * FROM userData";

	// SQL実行
	$res = $dbh->query($sql);

	// 取得したデータを出力
	foreach( $res as $value ) {
		echo "$value[id]<br>";
        echo "$value[name]<br>";
        echo "$value[password]<br>";
	}

} catch(PDOException $e) {
	echo $e->getMessage();
	die();
}

// 接続を閉じる
$dbh = null;