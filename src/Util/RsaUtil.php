<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk\Util;

/**
 * RSA 签名工具 — 对照后端 RsaSignUtil
 * 使用 PHP 内置 ext-openssl（openssl_sign / openssl_verify），算法 SHA256withRSA
 */
class RsaUtil
{
    /**
     * 全部空白与不可见字符。
     * PCRE 的 \s 默认只含 ASCII 空白，Unicode 空白（NEL / NBSP / 全角空格等）需显式列出；
     * 零宽空格 / 零宽连接符 / 词连接符 / BOM / 软连字符不属于空白，同样显式列出。
     */
    private const INVISIBLE_PATTERN = '/[\s\x{0085}\x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}\x{00ad}]+/u';

    /**
     * 剥掉 -----BEGIN xxx----- / -----END xxx----- 标记，返回中间内容
     * （标记之外的前后说明文字一并丢弃，与其它语言版本一致）
     */
    private static function stripArmor(string $text): string
    {
        $body = $text;
        $begin = strpos($body, '-----BEGIN');
        if ($begin !== false) {
            $body = substr($body, $begin + strlen('-----BEGIN'));
            // 跳过 " xxx-----" 到起始标记结束
            $close = strpos($body, '-----');
            if ($close !== false) {
                $body = substr($body, $close + strlen('-----'));
            }
        }
        $end = strpos($body, '-----END');
        if ($end !== false) {
            $body = substr($body, 0, $end);
        }
        return $body;
    }

    /**
     * 从任意形态的密钥文本中提取 DER。
     *
     * 从网页 / 聊天窗口 / PDF / IDE 复制 PEM 时，正文换行常被替换成空格或 NBSP，或整段压成一行、
     * 混入零宽字符，甚至只剩裸 Base64。这里统一归一：剥掉头尾标记、剔除全部空白与不可见字符，
     * 再按 Base64（含无填充变体）解出 DER（与 Go/Java/Node/Python 版同一套行为，见 Go 版 niudun/pem.go）。
     *
     * @param string $pemContent 密钥文本
     * @param string $label      报错用的名称（公钥 / 私钥）
     * @throws \InvalidArgumentException 归一后仍不是合法密钥内容
     */
    private static function decodeKeyContent(string $pemContent, string $label): string
    {
        if (trim($pemContent) === '') {
            throw new \InvalidArgumentException($label . '内容为空');
        }
        $body = preg_replace(self::INVISIBLE_PATTERN, '', self::stripArmor($pemContent));
        $body = $body === null ? '' : $body;
        if ($body === '') {
            throw new \InvalidArgumentException('未找到密钥内容，请确认已完整复制 PEM（含 BEGIN / END 两行）');
        }
        // 部分来源会去掉 Base64 末尾的填充等号
        $unpadded = rtrim($body, '=');
        if (preg_match('/^[A-Za-z0-9+\/]+$/', $unpadded) !== 1 || strlen($unpadded) % 4 === 1) {
            throw new \InvalidArgumentException('密钥内容不是合法的 Base64，请确认复制完整且未混入其它字符');
        }
        $der = base64_decode($unpadded . str_repeat('=', (4 - strlen($unpadded) % 4) % 4), true);
        if ($der === false) {
            throw new \InvalidArgumentException('密钥内容不是合法的 Base64，请确认复制完整且未混入其它字符');
        }
        return $der;
    }

    /**
     * 把 DER 重建成标准 PEM（OpenSSL 只认 PEM 文本）
     */
    private static function toPem(string $der, string $type): string
    {
        return "-----BEGIN {$type}-----\n"
            . chunk_split(base64_encode($der), 64, "\n")
            . "-----END {$type}-----\n";
    }

    /**
     * 加载公钥（X.509 优先，回退 PKCS#1）
     * 文本先经容错归一，兼容换行丢失 / 混入不可见字符的粘贴形态；不可解析返回 false
     *
     * @return \OpenSSLAsymmetricKey|resource|false
     */
    public static function loadPublicKey(string $publicKeyPem)
    {
        // 常规 PEM 直接交给 OpenSSL
        $key = @openssl_pkey_get_public($publicKeyPem);
        if ($key !== false) {
            return $key;
        }
        // 容错：归一后重建标准 PEM 再试（裸 Base64 / 换行被破坏的形态）
        try {
            $der = self::decodeKeyContent($publicKeyPem, '公钥');
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        foreach (['PUBLIC KEY', 'RSA PUBLIC KEY'] as $type) {
            $key = @openssl_pkey_get_public(self::toPem($der, $type));
            if ($key !== false) {
                return $key;
            }
        }
        return false;
    }

    /**
     * 加载私钥（PKCS#8 优先，回退 PKCS#1）
     * 文本先经容错归一，兼容换行丢失 / 混入不可见字符的粘贴形态；不可解析返回 false
     *
     * @return \OpenSSLAsymmetricKey|resource|false
     */
    public static function loadPrivateKey(string $privateKeyPem)
    {
        $key = @openssl_pkey_get_private($privateKeyPem);
        if ($key !== false) {
            return $key;
        }
        try {
            $der = self::decodeKeyContent($privateKeyPem, '私钥');
        } catch (\InvalidArgumentException $e) {
            return false;
        }
        foreach (['PRIVATE KEY', 'RSA PRIVATE KEY'] as $type) {
            $key = @openssl_pkey_get_private(self::toPem($der, $type));
            if ($key !== false) {
                return $key;
            }
        }
        return false;
    }

    /**
     * 私钥签名（SHA256withRSA，UTF-8 字节，Base64 输出）
     */
    public static function sign(string $data, string $privateKeyPem): string
    {
        $privateKey = self::loadPrivateKey($privateKeyPem);
        if ($privateKey === false) {
            throw new \RuntimeException('私钥解析失败：需为 PKCS#8 / PKCS#1 格式的 RSA 私钥');
        }
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, \OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('RSA 签名失败: ' . \openssl_error_string());
        }
        return base64_encode($signature);
    }

    /**
     * 公钥验签
     */
    public static function verify(string $data, string $signB64, string $publicKeyPem): bool
    {
        $publicKey = self::loadPublicKey($publicKeyPem);
        if ($publicKey === false) {
            return false;
        }
        $result = openssl_verify($data, base64_decode($signB64), $publicKey, \OPENSSL_ALGO_SHA256);
        return $result === 1;
    }

    /**
     * 校验 PKCS#8 私钥 PEM 是否可解析（联调 demo 保存配置时即时反馈格式错误）
     * 只做解析验证，不保留返回的密钥资源
     */
    public static function isValidPrivateKey(string $privateKeyPem): bool
    {
        return self::loadPrivateKey($privateKeyPem) !== false;
    }

    /**
     * 校验 X.509 公钥 PEM 是否可解析（联调 demo 保存配置时即时反馈格式错误）
     */
    public static function isValidPublicKey(string $publicKeyPem): bool
    {
        return self::loadPublicKey($publicKeyPem) !== false;
    }
}
