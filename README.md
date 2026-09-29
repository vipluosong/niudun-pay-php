# 牛盾支付 Open SDK for PHP

牛盾支付 开放支付平台 PHP SDK，封装支付、退款、转账、分账、网关共 15 个开放接口与回调验签。

> **适配 牛盾支付 Open ≥ 1.0** · **PHP 7.4+** · Apache-2.0 · 零第三方依赖（ext-openssl / ext-json）

## 功能

- RSA 双向签名（SHA256withRSA，`openssl_sign`），自动签名请求 / 验签响应与回调
- 走 JSON 签名路径，与开源版后端 `reqTime` 契约对齐
- 支付族：`pay` / `close` / `queryPayOrder` / `syncPayOrder`
- 退款族：`refund` / `queryRefundOrder` / `syncRefundOrder`
- 转账族：`transfer` / `queryTransferOrder` / `syncTransferOrder`
- 分账族：`alloc` / `queryAllocOrder` / `syncAllocOrder`
- 网关族：`gatewayPrePay` / `gatewayQuery`
- 探针与回调：`ping`（部署自检）/ `verifyNotice`（异步通知验签）
- 联调观测：`setObserver()` 拿到每次调用签名后的请求体与平台原始响应体（不设置时零开销）

## 安装（源码引入）

`composer.json`：

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/niudunpay/niudun-pay-sdk-php.git" }
    ],
    "require": {
        "niudun/open-sdk": "dev-main"
    }
}
```

```bash
composer install
```

```php
use NiuDun\OpenSdk\Client;
use NiuDun\OpenSdk\Config;
```

## 快速开始

```php
$config = (new Config())
    ->setServiceUrl('https://sandbox.niudunpay.cn')
    ->setMchNo('M200000001')
    ->setAppId('APP001')
    ->setPrivateKey($merchantPrivateKeyPem)     // PEM 文本
    ->setPublicKey($platformPublicKeyPem);       // PEM 文本
$client = new Client($config);

// 支付下单
$result = $client->pay([
    'bizOrderNo' => 'PAY20250805001',
    'title'      => '测试商品',
    'amount'     => 100,            // 分
    'method'     => 'wechat_qr',
    'notifyUrl'  => 'https://example.com/notify',
]);

// 回调验签
// $ok = $client->verifyNotice($rawBody);
```

> 完整可运行示例见 [`examples/pay.php`](examples/pay.php)。

## 联调 Demo（推荐入门方式）

仓内自带一个**单命令启动的联调 Demo**：内嵌调试页 + 全接口表单 + 代码预览 + 回调接收，
所有交易调用都经 `Client` 真实签名发出，同时验证 SDK 与平台 unipay 接口两侧。

### 1. 启动（无需任何配置文件）

```bash
php -S 127.0.0.1:9793 demo/router.php
```

浏览器打开 <http://127.0.0.1:9793>，页面为**三栏布局**：左侧接口导航（5 个业务域 / 15 个接口）、
中间表单与结果、右侧**随表单实时生成的 PHP 调用代码**（可直接复制到项目里用）。

> `php -S` 的内置服务器把全部请求都交给 `demo/router.php` 分发（含调试页与 `/callback/*` 回调接收端点）；
> 内置服务器为单线程串行，demo 级使用足够。

点击右上角 **「连接配置」** 打开弹窗填写参数，保存即生效：

| 字段 | 说明 |
|------|------|
| 平台服务地址 | 如 `http://127.0.0.1:9999` |
| 商户号 / 应用号 | 应用号可空（回落平台默认应用） |
| 商户私钥 | PKCS#8 PEM，粘贴后即时校验格式 |
| 平台公钥 | X.509 PEM，用于响应与回调验签 |

弹窗内 **「测试连接」** 按钮会经服务端中转调用平台自检探针 `GET /unipay/callback/ping`
（浏览器直连平台地址会跨域），可快速区分「地址写错」「网关未放行 /unipay/callback 前缀」「后端未启动」。
注意探针需平台版本包含该端点（`UnipayPingController`），旧版本会返回 401。

配置保存在**浏览器 localStorage**（仅本机），服务重启后打开页面自动恢复。
服务端另存一份**进程外的临时状态快照**（连接配置 + 回调记录）：`php -S` 内置服务器每个请求都是全新的执行上下文，
用户态内存无法跨请求保留，因此状态落在临时内存盘文件里 —— 优先 `/dev/shm`（Linux tmpfs＝内存盘），
回退系统临时目录，文件权限 `0600`，可用环境变量 `NIUDUN_DEMO_STATE` 指定路径。
状态文件里记录服务进程 PID，**服务重启后 PID 变化即视为全新会话、回到默认值**（与其它语言「重启即回默认值」语义一致）。
因此 PHP 版**不提供配置文件方式**（页面内配置已覆盖全部场景）。

### 2. 使用

- 左侧导航切换 **15 个开放接口**（支付 / 退款 / 转账 / 分账 / 网关五族），
  每个接口的表单都带必填校验与类型校验，嵌套结构（商品明细 / 终端信息 / 转账报备 / 分账接收方）
  用可增删的行编辑器填写
- 结果区回显「SDK 签名后的完整请求体 + 平台原始响应 + 响应验签结果 + 耗时」，
  支付类接口单独透出 `payBody` / `h5Url` / `confirmUrl` 等跳转地址
- **回调通知记录** 区实时轮询展示平台异步通知（自动验签）；
  表单 `notifyUrl` 填 Demo 提示的回调地址（默认已填好）即可完成「支付 → 回调 → 验签」全链路闭环

### 3. 请求参数约定

所有便捷方法入参均为**关联数组**（无参数对象），字段名与平台契约一致，金额一律整数**分**：

```php
// 支付下单（含嵌套：商品明细用列表、终端信息用关联数组）
$goodsDetail = [
    ['goodsId' => 'G001', 'goodsName' => '商品A', 'quantity' => 1, 'unitPrice' => 5000],
];
$terminal = ['terminalNo' => 'T001', 'storeNo' => 'S001'];

$result = $client->pay([
    'bizOrderNo'  => 'PAY20250805001',
    'title'       => '测试商品',
    'amount'      => 100,               // 分
    'method'      => 'wechat_qr',
    'goodsDetail' => $goodsDetail,
    'terminal'    => $terminal,
]);
echo $result['data']['payBody'];        // 二维码链接/调起参数

// 分账（接收方列表）
$receivers = [
    ['receiverType' => 'MERCHANT_ID', 'receiverAccount' => 'M200000002', 'amount' => 60],
];
$client->alloc(['bizAllocNo' => 'AL_001', 'tradeNo' => $result['data']['tradeNo'], 'receivers' => $receivers]);
```

各方法支持的字段与响应结构见 `src/Client.php` 的 PHPDoc（逐接口逐字段中文说明），
字段正典为 `_doc/design/sdk-contract.md` 第二节与 6.1–6.13。

## 接口文档

- [接入准备](https://doc.open.niudun.cn/api/getting-started) · [签名规则](https://doc.open.niudun.cn/api/signature)
- 黄金测试向量：见 [`tests/GoldenVectorTest.php`](tests/GoldenVectorTest.php)（与后端签名契约同源断言）

## License

Apache-2.0，可自由用于商业项目与闭源集成，协议全文见 [LICENSE](LICENSE)。主仓库 [牛盾支付 Open](https://gitee.com/niudunpay/niudun-pay) 核心为 LGPL-3.0-or-later，本 SDK 作为独立仓按 Apache-2.0 单独发布。

## 开源许可与来源

本项目基于 [DaxPay](https://github.com/opendaxpay) 开放的支付 SDK 改造，
按牛盾支付的命名规则重命名并适配，核心签名验签协议保持一致。

原项目采用 **Apache License 2.0**，本项目遵循同一许可：
`LICENSE` 文件中保留了原始版权与许可声明，任何修改均在源码中可见。
