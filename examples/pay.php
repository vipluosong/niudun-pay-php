<?php
declare(strict_types=1);

// 牛盾聚合支付下单示例 — PHP
// 运行前：composer install，启动后端（niudun-start，端口 9999），替换为真实商户密钥
require_once __DIR__ . '/../vendor/autoload.php';

use NiuDun\OpenSdk\Client;
use NiuDun\OpenSdk\Config;

// 商户私钥 + 平台公钥（生产环境从环境变量/配置中心读取，切勿硬编码）
$privateKey = <<<'PEM'
-----BEGIN PRIVATE KEY-----
（替换为你的商户私钥）
-----END PRIVATE KEY-----
PEM;

$publicKey = <<<'PEM'
-----BEGIN PUBLIC KEY-----
（替换为平台公钥）
-----END PUBLIC KEY-----
PEM;

$config = (new Config())
    ->setServiceUrl('http://127.0.0.1:9999')
    ->setMchNo('M200000001')
    ->setAppId('APP001')
    ->setPrivateKey($privateKey)
    ->setPublicKey($publicKey);
$client = new Client($config);

$result = $client->pay([
    'bizOrderNo' => 'PAY_' . intval(microtime(true) * 1000),
    'title'      => '测试商品',
    'amount'     => 100, // 分
    'method'     => 'wechat_qr',
    'notifyUrl'  => 'https://example.com/notify',
]);

$data = $result['data'] ?? [];
echo "订单号: " . ($data['orderNo'] ?? '') . "\n";
echo "交易号: " . ($data['tradeNo'] ?? '') . "\n";
echo "状态: " . ($data['status'] ?? '') . "\n";
echo "支付参数体: " . ($data['payBody'] ?? '') . "\n";
echo "支付参数体类型: " . ($data['payBodyType'] ?? '') . "\n";
