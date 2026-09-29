<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk\Tests;

use PHPUnit\Framework\TestCase;
use NiuDun\OpenSdk\Util\RsaUtil;

/**
 * 密钥文本容错测试 — 各种「能看不能用」的 PEM 粘贴形态都应解析出同一把密钥
 * 对照 Go 版 niudun/pem_test.go 同名用例：五语言 SDK 行为一致
 */
class PemToleranceTest extends TestCase
{
    use TestKeys;

    /**
     * 拆出 PEM 的头行 / 正文 / 尾行
     *
     * @return string[]
     */
    private function splitPem(string $pem): array
    {
        $lines = explode("\n", trim($pem));
        return [
            $lines[0],
            implode("\n", array_slice($lines, 1, count($lines) - 2)),
            $lines[count($lines) - 1],
        ];
    }

    /**
     * 把正文按 64 字符重新分行，行间以 sep 连接（sep 为空表示整段一行）
     */
    private function rewrap(string $body, string $sep): string
    {
        return implode($sep, str_split(str_replace("\n", '', $body), 64));
    }

    /**
     * 已加载密钥的标准 PEM（用于比对解析结果）
     *
     * @param mixed $key openssl 密钥资源 / OpenSSLAsymmetricKey
     */
    private function keyPem($key): string
    {
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        return $details['key'];
    }

    public function testPublicKeyVariants(): void
    {
        [$head, $body, $foot] = $this->splitPem($this->publicKey());
        $flat = $this->rewrap($body, '');
        $want = $this->keyPem(RsaUtil::loadPublicKey($this->publicKey()));

        $cases = [
            '标准 PEM' => $this->publicKey(),
            '正文单行不换行' => $head . "\n" . $flat . "\n" . $foot,
            '正文换行→空格' => $head . "\n" . $this->rewrap($body, ' ') . "\n" . $foot,
            '全文压成一行' => $head . ' ' . $this->rewrap($body, ' ') . ' ' . $foot,
            'BEGIN 行尾换行→空格' => $head . ' ' . $this->rewrap($body, "\n") . "\n" . $foot,
            'END 前换行→空格' => $head . "\n" . $this->rewrap($body, "\n") . ' ' . $foot,
            '正文含 NBSP' => $head . "\n" . substr($flat, 0, 64) . "\u{00a0}" . substr($flat, 64) . "\n" . $foot,
            'NBSP 当换行分隔符' => $head . "\n" . $this->rewrap($body, "\u{00a0}") . "\n" . $foot,
            '正文含零宽空格' => $head . "\n" . substr($flat, 0, 64) . "\u{200b}" . substr($flat, 64) . "\n" . $foot,
            '正文含 BOM' => $head . "\n" . substr($flat, 0, 64) . "\u{feff}" . substr($flat, 64) . "\n" . $foot,
            '裸 Base64（无头尾标记）' => $flat,
            'CRLF 换行' => str_replace("\n", "\r\n", $this->publicKey()),
            'CR 换行' => str_replace("\n", "\r", trim($this->publicKey())),
            '前后带说明文字' => "这是平台公钥：\n" . $this->publicKey() . "\n请妥善保管",
        ];

        foreach ($cases as $name => $text) {
            $key = RsaUtil::loadPublicKey($text);
            $this->assertNotFalse($key, '公钥形态解析失败：' . $name);
            $this->assertSame($want, $this->keyPem($key), '公钥形态解析不一致：' . $name);
        }
    }

    public function testPrivateKeyVariants(): void
    {
        [$head, $body, $foot] = $this->splitPem($this->privateKey());
        $flat = $this->rewrap($body, '');
        $want = $this->keyPem(RsaUtil::loadPrivateKey($this->privateKey()));

        $cases = [
            '标准 PEM' => $this->privateKey(),
            '全文压成一行' => $head . ' ' . $this->rewrap($body, ' ') . ' ' . $foot,
            '正文含 NBSP' => $head . "\n" . substr($flat, 0, 64) . "\u{00a0}" . substr($flat, 64) . "\n" . $foot,
            '裸 Base64（无头尾标记）' => $flat,
        ];

        foreach ($cases as $name => $text) {
            $key = RsaUtil::loadPrivateKey($text);
            $this->assertNotFalse($key, '私钥形态解析失败：' . $name);
            $this->assertSame($want, $this->keyPem($key), '私钥形态解析不一致：' . $name);
        }
    }

    public function testFlattenedPublicKeyStillVerifies(): void
    {
        [$head, $body, $foot] = $this->splitPem($this->publicKey());
        $flattened = $head . ' ' . $this->rewrap($body, ' ') . ' ' . $foot;
        $signStr = 'amount=100&appId=APP001';
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        $this->assertTrue(RsaUtil::verify($signStr, $sign, $flattened));
    }

    public function testValidateEntryAllowsFlattened(): void
    {
        [$head, $body, $foot] = $this->splitPem($this->publicKey());
        $flattened = $head . ' ' . $this->rewrap($body, ' ') . ' ' . $foot;
        $this->assertTrue(RsaUtil::isValidPublicKey($flattened));
        $this->assertTrue(RsaUtil::isValidPrivateKey($this->privateKey()));
    }

    public function testInvalidInputRejected(): void
    {
        $this->assertFalse(RsaUtil::loadPublicKey('   '), '空内容应被拒绝');
        $this->assertFalse(RsaUtil::loadPublicKey('这不是密钥'), '非密钥文本应被拒绝');
        $this->assertFalse(RsaUtil::loadPublicKey('-----BEGIN PUBLIC KEY-----'), '只有 BEGIN 无 END 应被拒绝');
        $this->assertFalse(RsaUtil::loadPublicKey('YWJjZGVmZ2g='), 'Base64 合法但非密钥应被拒绝');
    }
}
