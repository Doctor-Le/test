<?php
/**
 * 核心工具类方法。
 * -- 该类不封装任务与业无关的操作。
 *
 * @author 7031
 * @date   2019-03-04
 */

namespace app\utils;

use think\facade\Env;

class YCore
{
    /**
     * 抛出异常。
     *
     * @param int          $errCode            错误编号。
     * @param string|array $errMsg             错误信息。
     * @param string       $classNameAndMethod 出错位置执行的类与方法。当使用 try cacth 捕获异常时将捕获的异常信息传入。
     * @param string       $args               出错位置传入方法的参数。当使用 try cacth 捕获异常时将捕获的异常信息传入。
     *
     * @throws \app\exceptions\ServiceException
     */
    public static function exception($errCode, $errMsg, $classNameAndMethod = '', $args = [])
    {
        if (strlen($classNameAndMethod) === 0) {
            // debug_backtrace() 返回整个堆栈调用信息。
            // 堆栈里面的第二个数组返回的是调用 YCore::exception() 方法所在的类与方法相关信息。
            $result             = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT, 2);
            $classNameAndMethod = $result[1]['class'] . $result[1]['type'] . $result[1]['function'];
            $args               = $result[1]['args'];
        }
        throw new \app\exceptions\ServiceException($errMsg, $errCode, $classNameAndMethod, $args);
    }

    /**
     * 获取请求ip
     *
     * @return string ip地址
     */
    public static function ip()
    {
        $ip = '127.0.0.1';
        if (getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
            $ip = getenv('HTTP_CLIENT_IP');
        } elseif (getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
            $ip = getenv('HTTP_X_FORWARDED_FOR');
        } elseif (getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
            $ip = getenv('REMOTE_ADDR');
        } elseif (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp(
                $_SERVER['REMOTE_ADDR'], 'unknown'
            )) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return preg_match('/[\d\.]{7,15}/', $ip, $matches) ? $matches[0] : '';
    }

    /**
     * 字符串加密、解密函数
     *
     * @param string $txt       字符串
     * @param string $operation ENCODE为加密，DECODE为解密，可选参数，默认为ENCODE，
     * @param string $key       密钥：数字、字母、下划线
     * @param string $expiry    过期时间
     *
     * @return string
     */
    public static function sys_auth($string, $operation = 'ENCODE', $key = '', $expiry = 0)
    {
        $key_length    = 4;
        $key           = md5($key);
        $fixedkey      = md5($key);
        $egiskeys      = md5(substr($fixedkey, 16, 16));
        $runtokey      = $key_length ? ($operation == 'ENCODE' ? substr(md5(microtime(true)), -$key_length) : substr(
            $string, 0, $key_length
        )) : '';
        $keys          = md5(
            substr($runtokey, 0, 16) . substr($fixedkey, 0, 16) . substr($runtokey, 16) . substr($fixedkey, 16)
        );
        $string        = $operation == 'ENCODE' ? sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(
                md5($string . $egiskeys), 0, 16
            ) . $string : base64_decode(substr($string, $key_length));
        $i             = 0;
        $result        = '';
        $string_length = strlen($string);
        for ($i = 0; $i < $string_length; $i++) {
            $result .= chr(ord($string{$i}) ^ ord($keys{$i % 32}));
        }
        if ($operation == 'ENCODE') {
            return $runtokey . str_replace('=', '', base64_encode($result));
        } else {
            if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr(
                    $result, 10, 16
                ) == substr(md5(substr($result, 26) . $egiskeys), 0, 16)) {
                return substr($result, 26);
            } else {
                return '';
            }
        }
    }

    /**
     * 字符串星号处理器。
     *
     * @param string $str    被加星处理的字符串。
     * @param int    $start  星号起始位置。
     * @param int    $length 星号长度。
     *
     * @return string
     */
    public static function asterisk($str, $start, $length = 0)
    {
        $strLength = mb_strlen($str, 'UTF-8');
        $startStr  = ''; // 头部的字符串。
        $endStr    = ''; // 尾部的字符串。
        $asterisk  = ''; // 星号部分。
        $start     = $start >= 0 ? $start : 0;
        $start     = $start > $strLength ? $strLength : $start;
        $safeLen   = $strLength - $start; // 剩余可以被星号处理的安全长度。
        $length    = ($length <= $safeLen) ? $length : $safeLen;
        $length    = $length <= 0 ? $safeLen : $length;
        if ($start > 0) {
            $startStr = mb_substr($str, 0, $start, 'UTF-8');
        }
        if ($length != $safeLen) {
            $endStr = mb_substr($str, $start + $length, $length, 'UTF-8');;
        }
        $asterisk = str_repeat('*', $length);
        return $startStr . $asterisk . $endStr;
    }

    /**
     * 生成随机字符串
     *
     * @param string $lenth 长度
     *
     * @return string 字符串
     */
    public static function randomstr($lenth = 6)
    {
        return self::random($lenth, '123456789abcdefghijklmnpqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ');
    }

    /**
     * 产生随机字符串
     *
     * @param int    $length 输出长度
     * @param string $chars  可选的，默认为 0123456789
     *
     * @return string 字符串
     */
    public static function random($length, $chars = '0123456789')
    {
        $hash = '';
        $max  = strlen($chars) - 1;
        for ($i = 0; $i < $length; $i++) {
            $hash .= $chars[mt_rand(0, $max)];
        }
        return $hash;
    }

    /**
     * AES加密解密方法
     *              加密解密结果与 http://tool.chacuo.net/cryptaes 结果一致
     *              数据块128位
     *              key 为16位
     *              iv 为16位
     *              字符集utf-8
     *              输出为base64
     *              AES加密模式 为cbc
     *              填充 pkcs7padding
     *
     * @param string $string 加密解密字符串
     * @param string $type   操作类型 EN加密 DE解密
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/6/25 10:52
     *
     * @return string
     */
    public static function strCrypto($string, $type = 'DE')
    {
        $key    = Env::get('crypto.key');
        $iv     = Env::get('crypto.iv');
        $str    = '';
        $string = trim($string);
        if (!is_string($string) || strlen($string) == 0) {
            return $str;
        }
        if ($type == 'EN') { // 加密
            $str = base64_encode(openssl_encrypt($string, "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv));
            if ($str && self::strCrypto($str) != $string) {
                return false;
            }
            YLog::log(['明文' => $string, '密文' => $str], 'strCrypto', 'log');
        } elseif ($type == 'DE') { //解密
            $str = openssl_decrypt(base64_decode($string), "AES-128-CBC", $key, OPENSSL_RAW_DATA, $iv);
            $str = str_replace("\000", "", $str);
        }
        return $str;
    }

    /**
     * 自定义脱敏姓名 保证为汉字即可，如张三丰脱敏为张无忌、赵 三丰，均符合要求。
     *
     * @param string $fullName 姓名
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/7/31 9:15
     * @return string
     */
    public static function desensitizeName($fullName)
    {
        // [1] 非中文则直接返回
        if (!preg_match('/^[\x7f-\xff]+$/', $fullName)) {
            return $fullName;
        }
        // [2] 判断姓名长度
        $fullNameLength = mb_strlen($fullName);
        if ($fullNameLength <= 1) {
            return $fullName;
        }
        // [3] 获取姓
        $surName = self::getUserSurname($fullName);
        // [4] 获取名
        $name = str_replace($surName, '', $fullName);

        $nameArr       = [];
        $nameArrLength = mb_strlen($name);
        while ($nameArrLength) {//循环把字符串变为数组
            $nameArr[]     = mb_substr($name, 0, 1, 'utf8');
            $name          = mb_substr($name, 1, $nameArrLength, 'utf8');
            $nameArrLength = mb_strlen($name);
        }

        //获取所有汉字 共 20902
        $begin = hexdec("4e00"); //19968
        $end   = hexdec("9fa5"); //40869

        //        $a = ' ["';
        //        for ($i = $begin; $i <= $end; $i++) {
        //            $a .= '\u' . dechex($i);
        //        }
        //        $a .= '"] ';
        //        $b = json_decode($a);
        //        var_dump($b[0]);
        //        exit;

        foreach ($nameArr as $value) {
            $str    = self::utf8_str_to_unicode($value); // Unicode编码16进制  98DF
            $strNum = hexdec($str) - 110;                // Unicode编码10进制 39135
            $strNum = $strNum > $end ? $end : $strNum;
            $strNum = $strNum < $begin ? $begin : $strNum;
            $str    = dechex($strNum);
            $name   .= self::unicode_to_utf8($str);
        }
        return $surName . $name;
    }


    /**
     * utf8字符转换成Unicode字符
     *
     * @param  [type] $utf8_str Utf-8字符
     *
     * @return [type]      Unicode字符
     */
    public static function utf8_str_to_unicode($utf8_str)
    {
        $unicode = 0;
        $unicode = (ord($utf8_str[0]) & 0x1F) << 12;
        $unicode |= (ord($utf8_str[1]) & 0x3F) << 6;
        $unicode |= (ord($utf8_str[2]) & 0x3F);
        return dechex($unicode);
    }

    /**
     * Unicode字符转换成utf8字符
     *
     * @param  [type] $unicode_str Unicode字符
     *
     * @return [type]       Utf-8字符
     */
    public static function unicode_to_utf8($unicode_str)
    {
        $utf8_str = '';
        $code     = intval(hexdec($unicode_str));
        //这里注意转换出来的code一定得是整形，这样才会正确的按位操作
        $ord_1    = decbin(0xe0 | ($code >> 12));
        $ord_2    = decbin(0x80 | (($code >> 6) & 0x3f));
        $ord_3    = decbin(0x80 | ($code & 0x3f));
        $utf8_str = chr(bindec($ord_1)) . chr(bindec($ord_2)) . chr(bindec($ord_3));
        return $utf8_str;
    }

    /**
     * 获取姓氏
     *
     * @param string $username 姓名
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/7/31 9:18
     *
     * @return string
     */
    public static function getUserSurname($username)
    {
        $DoubleName = [
            "万俟",
            "司马",
            "上官",
            "欧阳",
            "夏侯",
            "诸葛",
            "闻人",
            "东方",
            "赫连",
            "皇甫",
            "尉迟",
            "公羊",
            "澹台",
            "公冶",
            "宗政",
            "濮阳",
            "淳于",
            "单于",
            "太叔",
            "申屠",
            "公孙",
            "仲孙",
            "轩辕",
            "令狐",
            "锺离",
            "宇文",
            "长孙",
            "慕容",
            "鲜于",
            "闾丘",
            "司徒",
            "司空",
            "丌官",
            "司寇",
            "子车",
            "微生",
            "颛孙",
            "端木",
            "巫马",
            "公西",
            "漆雕",
            "乐正",
            "壤驷",
            "公良",
            "拓拔",
            "夹谷",
            "宰父",
            "谷梁",
            "段干",
            "百里",
            "东郭",
            "南门",
            "呼延",
            "羊舌",
            "梁丘",
            "左丘",
            "东门",
            "西门",
            "南宫",
        ];
        //截取姓名中的前两个字符
        $surname = mb_substr($username, 0, 2, 'utf-8');
        if (!in_array($surname, $DoubleName)) {  //如果不在复姓数组中，则返回姓名中的第一个字
            $surname = mb_substr($username, 0, 1, 'utf-8');
        }
        return $surname;
    }

    /**
     * 身份证自定义脱敏
     *
     * 需满足以下条件：
     * 1. 身份证前两位数字（即省份代码）需为以下 34 个数字之一：
     *   11,12,13,14,15,21,22,23,31,32,33,34,35,36,37,41,42,43,44,45,46,50,51,52,53,54,61,62,63,64,65,71,81,82
     * 2. 身份证中的年月日需为现实中存在的日期
     *    如 360822198305022623 脱敏：
     *    原身份证 36 08 22 19830502 2623 脱敏规则 34 个数字之一
     *    任意数字 任意数字 真实存在的 日期 任意数
     *    脱敏示例
     *     1）、 36 99 99 19830502 2623
     *     2）、 36 99 99 19991231 2623
     *     3）、 11 52 19 19991231 2234
     *
     *  替换身份证 第3-6位  替换身份证 后四位（第15-18位）
     *
     * @param string $idCard 身份证
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/7/31 9:05
     *
     * @return string
     */
    public static function desensitizeIdCard($idCard)
    {
        // [1] 验证身份证
        if (!self::isIdCard($idCard)) {
            return $idCard;
        }
        // [2] 身份证前两位
        $prefix = mb_substr($idCard, 0, 2);
        // [3] 身份证 3-6位
        $middle       = mb_substr($idCard, 2, 4);
        $middleLength = strlen($middle);
        $middleArray  = [];
        while ($middleLength) {
            $middleArray[] = mb_substr($middle, 0, 1, 'utf8');
            $middle        = mb_substr($middle, 1, $middleLength, 'utf8');
            $middleLength  = mb_strlen($middle);
        }
        foreach ($middleArray as $value) {
            $middle .= self::numberConvert($value);
        }
        // [4] 身份证日期
        $birthDay = mb_substr($idCard, 6, 8);
        // [5] 身份证后四位
        $suffix       = mb_substr($idCard, 14, 4);
        $suffixLength = strlen($suffix);
        $suffixArray  = [];
        while ($suffixLength) {
            $suffixArray[] = mb_substr($suffix, 0, 1, 'utf8');
            $suffix        = mb_substr($suffix, 1, $suffixLength, 'utf8');
            $suffixLength  = mb_strlen($suffix);
        }
        foreach ($suffixArray as $value) {
            $suffix .= self::numberConvert($value);
        }
        // [6] 组装返回数据
        $idCardDesensitize = $prefix . $middle . $birthDay . $suffix;
        return $idCardDesensitize;
    }

    /**
     * 数字混淆转换
     *
     * @param int $number 数字
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/7/30 20:25
     *
     * @return mixed
     */
    public static function numberConvert($number)
    {
        $numberArray = [
            0 => 6,
            1 => 4,
            2 => 3,
            3 => 5,
            4 => 2,
            5 => 0,
            6 => 9,
            7 => 1,
            8 => 7,
            9 => 8,
        ];
        return isset($numberArray[$number]) ? $numberArray[$number] : $number;
    }

    /**
     * 验证身份证
     *
     * @param string $id 身份证
     *
     * @author 7279 <7279@jics.cn>
     * @date   2019/6/27 10:39
     *
     * @return bool
     */
    public static function isIdCard($id)
    {
        $id        = strtoupper($id);
        $regx      = "/(^\d{15}$)|(^\d{17}([0-9]|X)$)/";
        $arr_split = [];
        if (!preg_match($regx, $id)) {
            return false;
        }
        if (15 == strlen($id)) {//检查15位
            $regx = "/^(\d{6})+(\d{2})+(\d{2})+(\d{2})+(\d{3})$/";

            @preg_match($regx, $id, $arr_split);
            //检查生日日期是否正确
            $dtm_birth = "19" . $arr_split[2] . '/' . $arr_split[3] . '/' . $arr_split[4];
            if (!strtotime($dtm_birth)) {
                return false;
            } else {
                return true;
            }
        } else { //检查18位
            $regx = "/^(\d{6})+(\d{4})+(\d{2})+(\d{2})+(\d{3})([0-9]|X)$/";
            @preg_match($regx, $id, $arr_split);
            $dtm_birth = $arr_split[2] . '/' . $arr_split[3] . '/' . $arr_split[4];
            if (!strtotime($dtm_birth)) {  //检查生日日期是否正确
                return false;
            } else {
                //检验18位身份证的校验码是否正确。
                //校验位按照ISO 7064:1983.MOD 11-2的规定生成，X可以认为是数字10。
                $arr_int = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
                $arr_ch  = ['1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'];
                $sign    = 0;
                for ($i = 0; $i < 17; $i++) {
                    $b    = (int)$id{$i};
                    $w    = $arr_int[$i];
                    $sign += $b * $w;
                }
                $n       = $sign % 11;
                $val_num = $arr_ch[$n];
                if ($val_num != substr($id, 17, 1)) {
                    return false;
                } else {
                    return true;
                }
            }
        }
    }
}