<？php
/ **
 * PHP5.5の簡略化されたパスワードハッシュAPIとの互換性ライブラリ。
 *
 * @author Anthony Ferrara <ircmaxell@php.net>
 * @license http://www.opensource.org/licenses/mit-license.htmlMITライセンス
 * @ copyright2012著者 * /
 

名前空間{

    if（！defined（'PASSWORD_BCRYPT'））{
        / **
         * PHPUnitプロセス分離は定数をキャッシュしますが、関数宣言はキャッシュしません。
         *したがって、定数がとは別に定義されているかどうかを確認する必要があります 
         *ユーザーランドでのプロセス分離のサポートを可能にする機能
         *コード。
         * /
        定義（'PASSWORD_BCRYPT'、1）;
        定義（'PASSWORD_DEFAULT'、PASSWORD_BCRYPT）;
        定義（'PASSWORD_BCRYPT_DEFAULT_COST'、10）;
    }

    if（！function_exists（'password_hash'））{

        
         *指定されたアルゴリズムを使用してパスワードをハッシュします
         *
         * @param string $ passwordハッシュするパスワード
         * @param int $ algo使用するアルゴリズム（PASSWORD_ *定数で定義）
         * @param array $ options使用するアルゴリズムのオプション
         *
         * @return string | falseハッシュされたパスワード、またはエラーの場合はfalse。
         * /
        function  password_hash（$ password、$ algo、array  $ options = array（））{
            if（！function_exists（'crypt'））{
                trigger_error（"password_hashが機能するには、暗号をロードする必要があります"、E_USER_WARNING）;
                 nullを返す;
            }
            if（is_null（$ password）|| is_int（$ password））{
                $ password =（文字列） $ password ;
            }
            if（！is_string（$ password））{
                trigger_error（"password_hash（）：パスワードは文字列である必要があります"、E_USER_WARNING）;
                 nullを返す;
            }
            if（！is_int（$ algo））{
                でtrigger_error（"password_hash（）は、長さに2のパラメータを期待"。GETTYPE（$アルゴ）。"与えられた"、E_USER_WARNING）。
                 nullを返す;
            }
            $ resultLength = 0 ;
            スイッチ（$ algo）{
                ケース PASSWORD_BCRYPT：
                    $コスト= PASSWORD_BCRYPT_DEFAULT_COST ;
                    if（isset（$ options [ 'cost' ]））{
                        $ cost =（ int） $ options [ 'cost' ];
                        if（$ cost < 4 || $ cost > 31）{
                            trigger_error（sprintf（"password_hash（）：無効なbcryptコストパラメーターが指定されました：％d"、$ cost）、E_USER_WARNING）;
                             nullを返す;
                        }
                    }
                    //生成するソルトの長さ
                    $ raw_salt_len = 16 ;
                    //最終的なシリアル化に必要な長さ
                    $ required_salt_len = 22 ;
                    $ hash_format = sprintf（ "$ 2y $％02d $"、 $コスト）;
                    //最終的なcrypt（）出力の予想される長さ
                    $ resultLength = 60 ;
                    休憩;
                デフォルト：
                    trigger_error（sprintf（"password_hash（）：不明なパスワードハッシュアルゴリズム：％s"、$ algo）、E_USER_WARNING）;
                     nullを返す;
            }
            $ salt_req_encoding = false ;
            if（isset（$ options [ 'salt' ]））{
                switch（gettype（$ options [ 'salt' ]））{
                    ケース 'NULL'：
                    ケース 'ブール値'：
                    ケース '整数'：
                    ケース 'ダブル'：
                    ケース '文字列'：
                        $ salt =（ string） $ options [ 'salt' ];
                        休憩;
                    ケース 'オブジェクト'：
                        if（method_exists（$ options [ 'salt' ]、'__ tostring'））{
                            $ salt =（ string） $ options [ 'salt' ];
                            休憩;
                        }
                    ケース '配列'：
                    ケース 'リソース'：
                    デフォルト：
                        trigger_error（'password_hash（）：文字列以外のソルトパラメーターが指定されました'、E_USER_WARNING）;
                         nullを返す;
                }
                if（PasswordCompat \ binary \ _strlen（$ salt）< $ required_salt_len）{
                    trigger_error（sprintf（"password_hash（）：提供されたソルトが短すぎます：％dが％dを期待しています"、PasswordCompat \ binary \ _strlen（$ salt）、$ required_salt_len）、E_USER_WARNING）;
                     nullを返す;
                } ELSEIF（0 ==するpreg_match（'＃^ [a-zA-Z0-9./]+$#D' 、$塩））{
                    $ salt_req_encoding = true ;
                }
            } else {
                $バッファ= '' ;
                $ buffer_valid = false ;
                if（function_exists（'mcrypt_create_iv'）&&！defined（'PHALANGER'））{
                    $ buffer = mcrypt_create_iv（ $ raw_salt_len、 MCRYPT_DEV_URANDOM）;
                    if（$ buffer）{
                        $ buffer_valid = true ;
                    }
                }
                if（！$ buffer_valid && function_exists（'openssl_random_pseudo_bytes'））{
                    $ strong = false ;
                    $ buffer = openssl_random_pseudo_bytes（ $ raw_salt_len、 $ strong）;
                    if（$ buffer && $ strong）{
                        $ buffer_valid = true ;
                    }
                }
                もし（！$ buffer_valid && @ is_readable（'は/ dev / urandomの'））{
                    $ file = fopen（ '/ dev / urandom'、 'r'）;
                    $読み取り= 0 ;
                    $ local_buffer = '' ;
                    while（$ read < $ raw_salt_len）{
                        $ local_buffer =。のfread（ $ファイル、 $ raw_salt_len - $読み）。
                        $ read = PasswordCompat \ binary \ _strlen（ $ local_buffer）;
                    }
                    fclose（$ファイル）;
                    if（$ read > = $ raw_salt_len）{
                        $ buffer_valid = true ;
                    }
                    $ buffer = str_pad（ $ buffer、 $ raw_salt_len、 "\ 0"）^ str_pad（ $ local_buffer、 $ raw_salt_len、 "\ 0"）;
                }
                if（！$ buffer_valid || PasswordCompat \ binary \ _strlen（$ buffer）< $ raw_salt_len）{
                    $ buffer_length = PasswordCompat \ binary \ _strlen（ $ buffer）;
                    for（$ i = 0 ; $ i < $ raw_salt_len ; $ i ++）{
                        if（$ i < $ buffer_length）{
                            $バッファー[ $ I ] = $バッファー[ $ I ] ^ CHR（ mt_rand（ 0、 255））;
                        } else {
                            $バッファ=。 CHR（ mt_rand（ 0、 255））;
                        }
                    }
                }
                $ salt = $ buffer ;
                $ salt_req_encoding = true ;
            }
            if（$ salt_req_encoding）{
                // cryptで使用されるBase64バリアントで文字列をエンコードします
                $ base64_digits =
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 + /' ;
                $ bcrypt64_digits =
                    './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ;

                $ base64_string = base64_encode（ $ salt）;
                $ salt = strtr（ rtrim（ $ base64_string、 '='）、 $ base64_digits、 $ bcrypt64_digits）;
            }
            $ salt = PasswordCompat \ binary \ _substr（ $ salt、 0、 $ required_salt_len）;

            $ hash = $ hash_format。$塩;

            $ ret = crypt（ $ password、 $ hash）;

            if（！is_string（$ ret）|| PasswordCompat \ binary \ _strlen（$ ret）！= $ resultLength）{
                 falseを返します;
            }

             $ retを返します;
        }

        / **
         *パスワードハッシュに関する情報を取得します。情報の配列を返します
         *パスワードハッシュの生成に使用されたもの。
         *
         * array（
         * 'algo' => 1、
         * 'algoName' => 'bcrypt'、
         * 'オプション' => array（
         * 'コスト' => PASSWORD_BCRYPT_DEFAULT_COST、
         *）、
         *）
         *
         * @param string $ hash情報を抽出するためのパスワードハッシュ
         *
         * @returnarrayハッシュに関する情報の配列。
         * /
        function  password_get_info（$ hash）{
            $ return = array（
                'algo' => 0、
                'algoName' => '不明'、
                'オプション' =>配列（）、
            ）;
            もし（PasswordCompat \バイナリ\ _substr（$ハッシュ、0、4）== '$ 2Y $' && PasswordCompat \バイナリ\ _strlen（$ハッシュ）== 60）{
                $ return [ 'algo' ] = PASSWORD_BCRYPT ;
                $ return [ 'algoName' ] = 'bcrypt' ;
                list（$ cost）= sscanf（$ hash、"$ 2y $％d $"）;
                $ return [ 'options' ] [ 'cost' ] = $ cost ;
            }
            返す $リターンを。
        }

        / **
         *提供されたオプションに従ってパスワードハッシュを再ハッシュする必要があるかどうかを判断します
         *
         *答えがtrueの場合、password_verifyを使用してパスワードを検証した後、パスワードを再ハッシュします。
         *
         * @param string $ hashテストするハッシュ
         * @param int $ algo新しいパスワードハッシュに使用されるアルゴリズム
         * @param array $ optionspassword_hashに渡されるオプション配列
         *
         * @returnbooleanパスワードを再ハッシュする必要がある場合はTrue。
         * /
        function  password_needs_rehash（$ hash、$ algo、array  $ options = array（））{
            $ info = password_get_info（ $ hash）;
            if（$ info [ 'algo' ]！==（int）$ algo）{
                 trueを返します;
            }
            スイッチ（$ algo）{
                ケース PASSWORD_BCRYPT：
                    $ cost = isset（ $ options [ 'cost' ]）？（ int） $ options [ 'cost' ]： PASSWORD_BCRYPT_DEFAULT_COST ;
                    if（$ cost！== $ info [ 'options' ] [ 'cost' ]）{
                         trueを返します;
                    }
                    休憩;
            }
             falseを返します;
        }

        / **
         *タイミング攻撃に強いアプローチを使用して、ハッシュに対してパスワードを確認します
         *
         * @param string $ password確認するパスワード
         * @param string $ hash検証するハッシュ
         *
         * @returnbooleanパスワードがハッシュと一致する場合
         * /
        function  password_verify（$ password、$ hash）{
            if（！function_exists（'crypt'））{
                trigger_error（"password_verifyが機能するには、暗号をロードする必要があります"、E_USER_WARNING）;
                 falseを返します;
            }
            $ ret = crypt（ $ password、 $ hash）;
            if（！is_string（$ ret）|| PasswordCompat \ binary \ _strlen（$ ret）！= PasswordCompat \ binary \ _strlen（$ hash）|| PasswordCompat \ binary \ _strlen（$ ret）<= 13）{
                 falseを返します;
            }

            $ status = 0 ;
            for（$ i = 0 ; $ i < PasswordCompat \ binary \ _strlen（$ ret）; $ i ++）{
                $ status | =（ ord（ $ ret [ $ i ]）^ ord（ $ hash [ $ i ]））;
            }

             $ status === 0を返します;
        }
    }

}

名前空間 PasswordCompat \ binary {

    if（！function_exists（'PasswordCompat \\ binary \\ _ strlen'））{

        / **
         *文字列のバイト数を数える
         *
         * mbstring拡張子によって上書きされる可能性があるため、これに単純にstrlen（）を使用することはできません。
         *この場合、strlen（）は内部エンコーディングに基づいて*文字*の数をカウントします。A
         *バイトのシーケンスは、単一のマルチバイト文字と見なされる場合があります。
         *
         * @param string $ binary_string入力文字列
         *
         * @internal
         * @returnintバイト数
         * /
        function  _strlen（$ binary_string）{
            if（function_exists（'mb_strlen'））{
                 mb_strlen（$ binary_string、'8bit'）;を返します。
            }
             strlenを返す（$ binary_string）;
        }

        / **
         *バイト制限に基づいて部分文字列を取得します
         *
         * @see _strlen（）
         *
         * @param string $ binary_string入力文字列
         * @param int $ start
         * @param int $ length
         *
         * @internal
         * @returnstring部分文字列
         * /
        function  _substr（$ binary_string、$ start、$ length）{
            if（function_exists（'mb_substr'））{
                return  mb_substr（$ binary_string、$ start、$ length、'8bit'）;
            }
             substrを返す（$ binary_string、$ start、$ length）;
        }

        / **
         *現在のPHPバージョンがライブラリと互換性があるかどうかを確認します
         *
         * @returnbooleanチェック結果
         * /
        関数 チェック（）{
            static  $ pass = NULL ;

            if（is_null（$ pass））{
                if（function_exists（'crypt'））{
                    $ hash = '$ 2y $ 04 $ usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG' ;
                    $ test = crypt（ "password"、 $ hash）;
                    $ pass = $ test == $ hash ;
                } else {
                    $ pass = false ;
                }
            }
             $パスを返します;
        }

    }
}