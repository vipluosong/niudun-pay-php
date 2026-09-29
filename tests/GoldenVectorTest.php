<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk\Tests;

use PHPUnit\Framework\TestCase;
use NiuDun\OpenSdk\Util\SignUtil;
use NiuDun\OpenSdk\Util\RsaUtil;

/**
 * 黄金向量测试 — 四语言 SDK 签名行为一致性硬验收
 * 对照 _doc/design/sdk-test-vectors.md
 */
class GoldenVectorTest extends TestCase
{
    use TestKeys;

    public function testV1Basic(): void
    {
        $json = '{"mchNo":"M200000001","appId":"APP001","reqId":"REQ20250805143000001",' .
            '"reqTime":"2025-08-05 14:30:00","nonceStr":"5K8264ILTKCH16CQ2502SI8ZNMTM67VS",' .
            '"bizOrderNo":"PAY20250805143000001","title":"测试商品","amount":100,' .
            '"method":"wechat_qr","notifyUrl":"https://example.com/notify"}';
        $expectedSignStr = 'amount=100&appId=APP001&bizOrderNo=PAY20250805143000001&mchNo=M200000001' .
            '&method=wechat_qr&nonceStr=5K8264ILTKCH16CQ2502SI8ZNMTM67VS' .
            '&notifyUrl=https://example.com/notify&reqId=REQ20250805143000001' .
            '&reqTime=2025-08-05 14:30:00&title=测试商品';
        $expectedSign = 'nleBG/KSrl5UE4o6XKMYmZ/Oz+BgUeyHorB1TXYG9w5WJ4y0DxuUTubjXbwdW1pZ' .
            'KNwV022EdasVP5V1kQUStmYfDcHxbSaTM3c3/IYXNGM2xVlvh1geJA1JzNgL2ErUHhAZUhZYBk6RnjhzV' .
            'XQl3JRSipKyjx5jPfAcNrI7K5RbBlDvOzbLJw2Sce+lXZFGkgAmGD1LjoX5rFMk7pf7m9PF+Njm69bTI' .
            '3J45TLWlv1iTRHH4BZG6BOiKleoH3TfOn73QubxQ4/2HIwognTmKawGSR3vjiM7rvSCDosyC5d5ZVltR' .
            'eZiHA6/AsdmXcT/EKc7VhCzjP3YgHxBPyZElQ==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    public function testV2Nested(): void
    {
        $json = '{"mchNo":"M200000001","appId":"APP001","reqId":"REQ20250805143000002",' .
            '"reqTime":"2025-08-05 14:30:00","bizOrderNo":"PAY20250805143000002",' .
            '"title":"测试商品 & 附录","amount":8888,"method":"alipay_qr",' .
            '"attach":"{\"order\":\"order_0000001\"}",' .
            '"terminal":{"terminalNo":"T001","storeNo":"S001","operatorId":"OP01"},' .
            '"goodsDetail":[{"goodsId":"G001","goodsName":"商品A","quantity":1,"unitPrice":5000},' .
            '{"goodsId":"G002","goodsName":"商品B","quantity":2,"unitPrice":1944}]}';
        $expectedSignStr = 'amount=8888&appId=APP001&attach={"order":"order_0000001"}' .
            '&bizOrderNo=PAY20250805143000002&goodsDetail[0].goodsId=G001' .
            '&goodsDetail[0].goodsName=商品A&goodsDetail[0].quantity=1&goodsDetail[0].unitPrice=5000' .
            '&goodsDetail[1].goodsId=G002&goodsDetail[1].goodsName=商品B' .
            '&goodsDetail[1].quantity=2&goodsDetail[1].unitPrice=1944&mchNo=M200000001' .
            '&method=alipay_qr&reqId=REQ20250805143000002&reqTime=2025-08-05 14:30:00' .
            '&terminal.operatorId=OP01&terminal.storeNo=S001&terminal.terminalNo=T001' .
            '&title=测试商品 & 附录';
        $expectedSign = 'LyKKVoDfVtHHBrrFHg4faEVkqh53uNy1FaC/wXmA3QqCosFc2Ed7AK6F7D7i7Ulic' .
            '0fSzFmi2vw/Bzt0y+sba/UMVuKdUEum+nG6psCjGjwTVAwShoVAznxzKfhE5vxZaA0wxvaN2HHpjrTEq' .
            'JiyVjbrK6tkjjKcA67QyeJS+lu46p7MIhPjMMnExgxWPgkwtlee5XuHoKYlgDk4oReAf5srcxfLI5f44' .
            'KwJrhHJFEY7w1iYtpMqkF6Ont0Zp9+MNAfhyZqy5eLPk76TuLzBSPdBMb8cSlM/5qjuBlFnECaW8yj8e' .
            'FOyly9CN8071HjrHmxv002BqEA1BXZ9Sqdh5g==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    public function testV3Verify(): void
    {
        // resTime 使用北京时间（平台对外契约）
        $json = '{"code":0,"msg":"success","data":{"bizOrderNo":"PAY20250805143000001",' .
            '"orderNo":"DEV_P20250805143000001","tradeNo":"T202508051430","status":"success",' .
            '"amount":100,"payBody":"https://example.com/pay?token=abc123"},' .
            '"reqId":"REQ20250805143000001","resTime":"2025-08-05 14:30:00"}';
        $expectedSignStr = 'code=0&data.amount=100&data.bizOrderNo=PAY20250805143000001' .
            '&data.orderNo=DEV_P20250805143000001&data.payBody=https://example.com/pay?token=abc123' .
            '&data.status=success&data.tradeNo=T202508051430&msg=success' .
            '&reqId=REQ20250805143000001&resTime=2025-08-05 14:30:00';
        $expectedSign = 'juvn6a3t8AHlD6XJHUFdaMXPFb/BfMCCnfUC8/oledpfitYRvWmZBrjrQlwmuqybhaeeyk' .
            'O3ds5AZT4fqE59duVjAeV9YxoVhsnJ+Sk/x6hAYnd70z+zWHP0AzKIip1EfGwx5/GsiOfz' .
            'yuh3u0RlP1lBAdPMqdXf12I69mZjyNGWv2WplggV95PRX6bqlXVTPwfgTnJHSobKL4z0rN' .
            'D0nTg/+qBqh8Px8aeNwLDh6mrpuLL6PKWVf9pmMzHhJzoj/CYJ2Ith8ciFdyVVB9vadAbk' .
            'xg6JUjgaZ41S5+W2tQrrdw/oJ7GFcYHuDwmeKKVeZKu+nMrA5TtY5PQj+CrK3Q==';

        $signStr = SignUtil::buildSignStr($json);
        self::assertSame($expectedSignStr, $signStr);
        $sign = RsaUtil::sign($signStr, $this->privateKey());
        self::assertSame($expectedSign, $sign);
        self::assertTrue(RsaUtil::verify($signStr, $sign, $this->publicKey()));
    }

    /**
     * PEM 解析校验（联调 demo 保存配置时用）：
     * 合法 PEM 通过、格式非法/内容损坏/空串一律不通过（避免无效密钥进入配置后才在交易时暴露）
     */
    public function testPemValidation(): void
    {
        self::assertTrue(RsaUtil::isValidPrivateKey($this->privateKey()));
        self::assertTrue(RsaUtil::isValidPublicKey($this->publicKey()));

        // 空串与随机文本
        self::assertFalse(RsaUtil::isValidPrivateKey(''));
        self::assertFalse(RsaUtil::isValidPublicKey(''));
        self::assertFalse(RsaUtil::isValidPrivateKey('not-a-pem'));
        self::assertFalse(RsaUtil::isValidPublicKey('not-a-pem'));

        // 头尾正确但 base64 体损坏
        $broken = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        self::assertFalse(RsaUtil::isValidPrivateKey($broken));

        // 公私钥两者必须严格区分，不能互相通过
        self::assertFalse(RsaUtil::isValidPrivateKey($this->publicKey()));
        self::assertFalse(RsaUtil::isValidPublicKey($this->privateKey()));
    }
}
