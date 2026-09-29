<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk\Util;

/**
 * 签名字符串构造 — 严格复刻后端 JsonSignStrUtil
 * 输入 JSON 字符串 → 扁平化 → ASCII 字典序排序 → 排除 sign（大小写不敏感）→ k=v&k=v
 */
class SignUtil
{
    /**
     * 构造待签名字符串
     */
    public static function buildSignStr(string $jsonStr): string
    {
        // JSON_BIGINT_AS_STRING：超大整数保持字面量，避免 float 精度丢失（对照 Go json.Number / Node 原始字面）
        $root = json_decode($jsonStr, true, 512, \JSON_BIGINT_AS_STRING);
        $flat = [];
        self::flatten('', $root, $flat);
        ksort($flat, \SORT_STRING); // ASCII 字典序
        $parts = [];
        foreach ($flat as $k => $v) {
            if (strcasecmp($k, 'sign') === 0) {
                continue;
            }
            $parts[] = $k . '=' . $v;
        }
        return implode('&', $parts);
    }

    /**
     * 验签：对 JSON 字符串构建签名串后用公钥验签
     */
    public static function verify(string $jsonStr, string $sign, string $publicKeyPem): bool
    {
        $obj = json_decode($jsonStr, true, 512, \JSON_BIGINT_AS_STRING);
        if (!isset($obj['sign']) || $obj['sign'] === '') {
            return false;
        }
        $signStr = self::buildSignStr($jsonStr);
        return RsaUtil::verify($signStr, $sign, $publicKeyPem);
    }

    /**
     * 扁平化（对照后端 JsonSignStrUtil#flatten）
     * null 跳过; bool/数字/字符串转字符串; list 用 [i]; map 用 .key
     */
    private static function flatten(string $prefix, $value, array &$result): void
    {
        if ($value === null) {
            return;
        }
        if (is_bool($value)) {
            $result[$prefix] = $value ? 'true' : 'false';
            return;
        }
        if (is_int($value) || is_float($value)) {
            $result[$prefix] = (string) $value;
            return;
        }
        if (is_string($value)) {
            $result[$prefix] = $value;
            return;
        }
        if (is_array($value)) {
            if (self::isArrayList($value)) {
                $i = 0;
                foreach ($value as $item) {
                    self::flatten($prefix . '[' . $i . ']', $item, $result);
                    $i++;
                }
            } else {
                foreach ($value as $k => $v) {
                    $key = $prefix === '' ? (string) $k : $prefix . '.' . $k;
                    self::flatten($key, $v, $result);
                }
            }
        }
    }

    /**
     * 判断是否为 list（连续 0..n-1 索引）— 兼容 PHP 7.4（无 array_is_list）
     */
    private static function isArrayList(array $arr): bool
    {
        if (empty($arr)) {
            return true;
        }
        return array_keys($arr) === range(0, count($arr) - 1);
    }
}
