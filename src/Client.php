<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk;

use NiuDun\OpenSdk\Util\SignUtil;
use NiuDun\OpenSdk\Util\RsaUtil;

/**
 * 牛盾聚合支付 SDK 客户端 — 对照 sdk-contract.md 第十节
 * 走 JSON 签名路径（reqTime 已序列化为 GMT+8 字面量），与后端验签一致
 *
 * 请求参数统一为**关联数组**（无参数对象），字段名与平台契约一致；
 * 金额字段一律为整数**分**；响应统一返回 NiuDunResult 关联数组（code/msg/data/sign/resTime/reqId）。
 */
class Client
{
    /** @var Config SDK 配置（服务地址 / 商户号 / 应用号 / 密钥对） */
    private Config $config;

    /**
     * @var array{0: ?callable, 1: ?callable}|null 调用观测钩子 [onRequest, onResponse]
     *      不设置时为 null（零开销）；联调 demo 用它拿到签名后请求体与平台原始响应
     */
    private ?array $observer = null;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * 设置调用观测钩子（联调/排障用）— 对照 NiuDunObserver
     *
     * - `$onRequest(string $signedJson)`：请求**已签名、即将发出**时回调，参数为含 sign 的完整请求 JSON；
     * - `$onResponse(string $rawBody)`：收到平台原始响应体时回调，**在响应验签之前**，验签失败也能拿到原文。
     *
     * 两个参数均可传 null 表示不关心该侧；不调用本方法时全程零开销。
     * 并发场景建议**每次调用创建独立的 Client 实例**，避免观察状态相互覆盖。
     *
     * @param callable|null $onRequest  签名后请求体回调，签名 `function (string $signedJson): void`
     * @param callable|null $onResponse 原始响应体回调，签名 `function (string $rawBody): void`
     * @return $this 链式调用
     */
    public function setObserver(?callable $onRequest = null, ?callable $onResponse = null): self
    {
        $this->observer = ($onRequest === null && $onResponse === null) ? null : [$onRequest, $onResponse];
        return $this;
    }

    /**
     * 通用执行入口：自动填充公共参数 → JSON 签名 → POST → 验签 → 返回关联数组
     *
     * 验签策略（对照 Java 版逐字一致）：
     * 1. 响应**带** sign：强制验签，失败抛「响应验签失败」；
     * 2. 响应**不带** sign 且 code == 0：抛「响应缺少签名，无法验证来源」（防伪造成功响应）；
     * 3. 响应**不带** sign 且 code != 0：直接透出业务码与消息（平台业务异常响应无签名，不视为验签失败）；
     * 4. 消息字段兼容：msg 为空时回退读 message。
     *
     * @param string $path  平台接口路径（如 /unipay/pay）
     * @param array<string,mixed> $param 请求参数（公共字段 mchNo/appId/reqId/reqTime/nonceStr 缺省自动注入）
     * @param bool $throwOnBizError 非 0 业务码是否抛异常（默认 true，既有方法行为不变）；
     *      传 false 时非 0 业务码不抛异常而是原样返回 NiuDunResult（签名自检探针的职责是报告检查结果，
     *      失败码/失败消息本身就是有效答案）；响应验签失败**仍抛**（平台公钥配置问题属于硬错误而非探针答案）
     * @return array<string,mixed> NiuDunResult 关联数组
     */
    public function execute(string $path, array $param, bool $throwOnBizError = true): array
    {
        // 注入公共字段
        $param['mchNo'] = $param['mchNo'] ?? $this->config->getMchNo();
        if ($this->config->getAppId() !== null) {
            $param['appId'] = $param['appId'] ?? $this->config->getAppId();
        }
        $param['reqId'] = $param['reqId'] ?? $this->generateReqId();
        $param['reqTime'] = $param['reqTime'] ?? $this->nowGmt8();
        $param['nonceStr'] = $param['nonceStr'] ?? $this->generateNonce();

        // 走 JSON 签名路径
        $jsonFlags = \JSON_UNESCAPED_UNICODE | \JSON_UNESCAPED_SLASHES;
        $jsonForSign = json_encode($param, $jsonFlags);
        $signStr = SignUtil::buildSignStr($jsonForSign);
        $param['sign'] = RsaUtil::sign($signStr, $this->config->getPrivateKey());
        $body = json_encode($param, $jsonFlags);

        // 观测钩子：请求已签名、即将发出
        if ($this->observer !== null && $this->observer[0] !== null) {
            ($this->observer[0])($body);
        }

        // POST
        $url = $this->config->getServiceUrl() . $path;
        $rawBody = $this->httpPost($url, $body);

        // 观测钩子：平台原始响应体（验签之前）
        if ($this->observer !== null && $this->observer[1] !== null) {
            ($this->observer[1])($rawBody);
        }

        // 验签（用原始 body 字符串）
        $result = json_decode($rawBody, true, 512, \JSON_BIGINT_AS_STRING);
        if (!is_array($result)) {
            throw new \RuntimeException('响应解析失败: ' . $rawBody);
        }
        $signed = isset($result['sign']) && $result['sign'] !== '';
        // 业务码按数值语义比较（对照 Java 版 getInt：字符串 "0" 同样视为成功；缺失/非数值按 -1 处理）
        $code = $result['code'] ?? -1;
        $code = is_numeric($code) ? (int) $code : -1;
        if ($signed) {
            if (!SignUtil::verify($rawBody, $result['sign'], $this->config->getPublicKey())) {
                throw new \RuntimeException('响应验签失败');
            }
        } elseif ($code === 0) {
            // 成功响应必须带签名，否则来源不可信（防伪造成功响应）
            throw new \RuntimeException('响应缺少签名，无法验证来源');
        }
        if ($code !== 0) {
            // 消息读取兼容：平台业务异常响应字段名为 message（NiuDunResult 为 msg）
            $msg = $result['msg'] ?? '';
            if ($msg === '' || $msg === null) {
                $msg = $result['message'] ?? '';
            }
            if (!$throwOnBizError) {
                // 非 0 业务码不抛异常而是原样返回 NiuDunResult（探针诊断路径；msg 已回填兼容值）
                $result['msg'] = $msg;
                return $result;
            }
            throw new \RuntimeException('[' . $code . '] ' . $msg);
        }
        return $result;
    }

    /**
     * 支付下单 — POST /unipay/pay
     *
     * @param array<string,mixed> $param 支付参数：
     *  - `bizOrderNo` string 商户订单号（必填）
     *  - `title` string 支付标题（必填）
     *  - `amount` int 支付金额（分，必填）
     *  - `description` string 支付描述
     *  - `currency` string 币种 ISO 4217，缺省 cny
     *  - `product` string 支付产品编码（空则通道路由自动选择）
     *  - `method` string 支付方式编码（如 wechat_qr / alipay_qr / wechat_barcode）
     *  - `capability` string 支付能力编码
     *  - `openId` string 用户 OpenId（微信 jsapi/mini 场景必填）
     *  - `channelAppId` string 通道应用 AppId（微信 wxAppId 等）
     *  - `authCode` string 付款码（被扫支付必填）
     *  - `limitPay` array 限制支付类型（如 ['no_credit']）
     *  - `extraParam` string 支付扩展参数（JSON 字符串，通道特有长尾参数）
     *  - `notifyUrl` string 异步通知地址
     *  - `returnUrl` string 同步跳转地址
     *  - `attach` string 商户扩展参数，回调原样返回
     *  - `expiredTime` string 过期时间（GMT+8 yyyy-MM-dd HH:mm:ss）
     *  - `goodsDetail` array 订单商品明细（元素：goodsId/goodsName/quantity/unitPrice/category/description/showUrl）
     *  - `terminal` array 终端信息（terminalNo/storeNo/operatorId/deviceName/deviceIp/longitude/latitude）
     *  - `source` string 订单来源标识
     *  - `allocation` bool 是否分账订单（分账链路前置条件）
     * @return array<string,mixed> NiuDunResult；`data` 为下单结果：
     *  bizOrderNo / orderNo / tradeNo / status（资金态：init|processing|success|fail|close|cancel）/
     *  payBody（二维码链接或调起参数或跳转 URL）/ payBodyType（code_url|pay_info|redirect_url）
     */
    public function pay(array $param): array
    {
        return $this->execute('/unipay/pay', $param);
    }

    /**
     * 关闭/撤销订单 — POST /unipay/close（响应 data 为 null，凭 code == 0 判断成功）
     *
     * @param array<string,mixed> $param 关闭参数：
     *  - `orderNo` string 平台支付订单号（tradeNo）或网关订单号，与 bizOrderNo 二选一，优先本字段
     *  - `bizOrderNo` string 商户订单号
     *  - `useCancel` bool 是否使用撤销方式（部分通道支持，不支持则忽略）
     * @return array<string,mixed> NiuDunResult（data 恒为 null）
     */
    public function close(array $param): array
    {
        return $this->execute('/unipay/close', $param);
    }

    /**
     * 查询支付订单 — POST /unipay/query/pay-order
     *
     * @param array<string,mixed> $param 查询参数：
     *  - `orderNo` string 平台业务单号，与 bizOrderNo 二选一，优先本字段
     *  - `bizOrderNo` string 商户订单号
     * @return array<string,mixed> NiuDunResult；`data` 为支付订单：
     *  bizOrderNo / orderNo / tradeNo / outOrderNo / title / description / channel / method / limitPay /
     *  amount / currency / realAmount / refundableBalance / status / refundStatus / provider / payTime / closeTime /
     *  expiredTime / terminalNo / storeNo / buyerId / attach / errorMsg
     */
    public function queryPayOrder(array $param): array
    {
        return $this->execute('/unipay/query/pay-order', $param);
    }

    /**
     * 支付订单同步 — POST /unipay/sync/order/pay
     * 主动向通道拉取支付单最新状态并回写本地（回调丢失的兜底补偿）
     *
     * @param array<string,mixed> $param 同步参数（orderNo / bizOrderNo / outOrderNo 至少传一个）：
     *  - `orderNo` string 平台业务单号
     *  - `bizOrderNo` string 商户订单号
     *  - `outOrderNo` string 通道系统交易号
     * @return array<string,mixed> NiuDunResult；`data` 含 orderStatus（同步后的订单状态）与 adjust（本次是否订正了本地状态）
     */
    public function syncPayOrder(array $param): array
    {
        return $this->execute('/unipay/sync/order/pay', $param);
    }

    /**
     * 退款 — POST /unipay/refund
     *
     * @param array<string,mixed> $param 退款参数：
     *  - `tradeNo` string 原支付资金交易号，与 bizOrderNo 二选一，优先本字段
     *  - `bizOrderNo` string 原支付商户业务订单号
     *  - `amount` int 退款金额（分，必填，>0，支持部分退款）
     *  - `reason` string 退款原因
     *  - `bizRefundNo` string 商户退款号（不传则系统生成）
     * @return array<string,mixed> NiuDunResult；`data` 为 refundNo / bizRefundNo / status / errorMsg
     */
    public function refund(array $param): array
    {
        return $this->execute('/unipay/refund', $param);
    }

    /**
     * 查询退款订单 — POST /unipay/query/refund-order
     *
     * @param array<string,mixed> $param 查询参数：
     *  - `refundNo` string 平台退款号，与 bizRefundNo 二选一，优先本字段
     *  - `bizRefundNo` string 商户退款号
     * @return array<string,mixed> NiuDunResult；`data` 为退款订单：
     *  refundNo / bizRefundNo / tradeNo / bizOrderNo / outRefundNo / amount / orderAmount /
     *  status / reason / finishTime / errorMsg
     */
    public function queryRefundOrder(array $param): array
    {
        return $this->execute('/unipay/query/refund-order', $param);
    }

    /**
     * 退款订单同步 — POST /unipay/sync/order/refund
     *
     * @param array<string,mixed> $param 同步参数：
     *  - `refundNo` string 平台退款号，与 bizRefundNo 二选一，优先本字段
     *  - `bizRefundNo` string 商户退款号
     * @return array<string,mixed> NiuDunResult；`data` 含 orderStatus 与 adjust（是否订正本地状态）
     */
    public function syncRefundOrder(array $param): array
    {
        return $this->execute('/unipay/sync/order/refund', $param);
    }

    /**
     * 转账 — POST /unipay/transfer（通道直连转账）
     * 幂等维度：通道 + 商户转账号 + 商户号；同组合重复发起会拦截，失败单可复用原单号重试
     *
     * @param array<string,mixed> $param 转账参数：
     *  - `channel` string 转账通道（wechat / alipay / douyin，必填）
     *  - `channelMchNo` string 通道商户号（转账凭证组装与通道路由用，必填）
     *  - `bizTransferNo` string 商户转账号（幂等键，必填）
     *  - `amount` int 转账金额（分，必填）
     *  - `title` string 转账标题
     *  - `reason` string 转账原因/备注
     *  - `payeeType` string 收款人账号类型（微信=openid；支付宝=user_id/open_id/login_name；抖音=openid/phone）
     *  - `payeeAccount` string 收款人账号
     *  - `payeeName` string 收款人姓名（微信：小于 0.3 元禁填，大于等于 2000 元必填）
     *  - `attach` string 商户扩展参数，回调原样返回
     *  - `notifyUrl` string 异步通知地址
     *  - `reportInfos` array 转账场景报备信息（元素：infoType/infoContent，微信转账场景必填）
     *  - `transferScene` string 转账场景标识（支付宝=场景配置 ID；抖音=枚举码如 1001；微信不传）
     * @return array<string,mixed> NiuDunResult；`data` 为 transferNo / bizTransferNo / status / confirmUrl（部分通道需收款人确认收款）
     */
    public function transfer(array $param): array
    {
        return $this->execute('/unipay/transfer', $param);
    }

    /**
     * 查询转账订单 — POST /unipay/query/transfer-order（仅查本地单，不调通道）
     *
     * @param array<string,mixed> $param 查询参数：
     *  - `transferNo` string 平台转账单号（单独可查）
     *  - `channel` string 转账通道（与 bizTransferNo 配对使用）
     *  - `bizTransferNo` string 商户转账号（须与 channel 成对传入）
     * @return array<string,mixed> NiuDunResult；`data` 为转账订单：
     *  transferNo / bizTransferNo / outTransferNo / relationNo / amount / currency / channel /
     *  provider / status / title / finishTime / errorMsg
     */
    public function queryTransferOrder(array $param): array
    {
        return $this->execute('/unipay/query/transfer-order', $param);
    }

    /**
     * 转账订单同步 — POST /unipay/sync/order/transfer（主动拉通道最新状态并回写本地）
     *
     * @param array<string,mixed> $param 同步参数：
     *  - `transferNo` string 平台转账单号（单独可查）
     *  - `channel` string 转账通道（与 bizTransferNo 配对使用）
     *  - `bizTransferNo` string 商户转账号（须与 channel 成对传入）
     * @return array<string,mixed> NiuDunResult；`data` 含 orderStatus 与 adjust（是否订正本地状态）
     */
    public function syncTransferOrder(array $param): array
    {
        return $this->execute('/unipay/sync/order/transfer', $param);
    }

    /**
     * 分账 — POST /unipay/alloc
     * 原支付订单须在**下单时声明** `allocation=true`，否则通道拒绝分账；
     * 接收方列表直接传入完整明细（极简模式，接收方绑定由调用方提前在通道侧完成）
     *
     * @param array<string,mixed> $param 分账参数：
     *  - `bizAllocNo` string 商户分账单号（幂等键，同一应用下唯一，必填）
     *  - `tradeNo` string 原支付资金交易号，与 bizOrderNo 二选一，优先本字段
     *  - `bizOrderNo` string 原支付商户业务订单号
     *  - `title` string 分账标题
     *  - `description` string 分账描述
     *  - `receivers` array 接收方列表（至少一个，必填）；元素：
     *      receiverType（MERCHANT_ID / PERSONAL_OPENID / PERSONAL_SUB_OPENID / USER_ID / LOGIN_NAME）/
     *      receiverAccount / receiverName / amount（分）
     *  - `attach` string 商户扩展参数，回调原样返回
     *  - `notifyUrl` string 异步通知地址
     * @return array<string,mixed> NiuDunResult；`data` 为 allocNo / bizAllocNo / status / errorMsg
     */
    public function alloc(array $param): array
    {
        return $this->execute('/unipay/alloc', $param);
    }

    /**
     * 查询分账订单 — POST /unipay/query/alloc-order（仅查本地单，不调通道）
     *
     * @param array<string,mixed> $param 查询参数：
     *  - `allocNo` string 平台分账单号，与 bizAllocNo 二选一，优先本字段
     *  - `bizAllocNo` string 商户分账单号
     * @return array<string,mixed> NiuDunResult；`data` 为分账订单：
     *  allocNo / bizAllocNo / tradeNo / bizOrderNo / outAllocNo / amount / status / finishTime /
     *  channel / attach / errorMsg / details（分账接收方明细列表：receiverType/receiverAccount/
     *  receiverName/amount/result/errorMsg/finishTime）
     */
    public function queryAllocOrder(array $param): array
    {
        return $this->execute('/unipay/query/alloc-order', $param);
    }

    /**
     * 分账订单同步 — POST /unipay/sync/order/alloc（主动向通道拉取分账单最新状态并回写本地）
     *
     * @param array<string,mixed> $param 同步参数：
     *  - `allocNo` string 平台分账单号，与 bizAllocNo 二选一，优先本字段
     *  - `bizAllocNo` string 商户分账单号
     * @return array<string,mixed> NiuDunResult；`data` 含 orderStatus 与 adjust（是否订正本地状态）
     */
    public function syncAllocOrder(array $param): array
    {
        return $this->execute('/unipay/sync/order/alloc', $param);
    }

    /**
     * 网关预下单 — POST /unipay/gateway/pre-pay
     * 产品语义「网关支付」：由平台收银台承接支付项选择与调起，商户侧只需拿到跳转地址
     *
     * @param array<string,mixed> $param 下单参数：
     *  - `bizOrderNo` string 商户订单号（必填）
     *  - `title` string 支付标题（必填）
     *  - `amount` int 支付金额（分，必填）
     *  - `gatewayPayType` string 网关支付类型（cashier=统一收银台；aggregate=聚合扫码一码多付，必填）
     *  - `description` string 支付描述
     *  - `currency` string 币种 ISO 4217，缺省 cny
     *  - `notifyUrl` string 异步通知地址
     *  - `returnUrl` string 同步跳转地址
     *  - `attach` string 商户扩展参数，回调原样返回
     *  - `extraParam` string 支付扩展参数（JSON 字符串）
     *  - `expiredTime` string 过期时间（GMT+8 yyyy-MM-dd HH:mm:ss）
     *  - `storeNo` string 门店编号
     *  - `goodsDetail` array 订单商品明细（元素同 pay）
     *  - `allocation` bool 是否分账订单
     * @return array<string,mixed> NiuDunResult；`data` 为 orderNo / bizOrderNo / status / gatewayType /
     *  h5Url（H5 收银台跳转地址）/ miniUrl（小程序收银台跳转地址）/ expiredTime
     */
    public function gatewayPrePay(array $param): array
    {
        return $this->execute('/unipay/gateway/pre-pay', $param);
    }

    /**
     * 网关订单查询 — POST /unipay/gateway/query
     * 与其它接口不同，本接口的 mchNo / appId 是**参数自身的可选字段**（用于网关侧按应用定位订单），
     * 留空时由 SDK 注入连接配置中的默认值
     *
     * @param array<string,mixed> $param 查询参数：
     *  - `orderNo` string 平台网关单号
     *  - `bizOrderNo` string 商户业务单号
     *  - `appId` string 应用号（留空由 SDK 注入）
     *  - `mchNo` string 商户号（留空由 SDK 注入）
     * @return array<string,mixed> NiuDunResult；`data` 为网关订单：
     *  orderNo / bizOrderNo / gatewayType / title / description / amount / currency / status /
     *  expiredTime / payTime / channel / method / product / tradeNo / outOrderNo / fundStatus /
     *  attach / returnUrl
     */
    public function gatewayQuery(array $param): array
    {
        return $this->execute('/unipay/gateway/query', $param);
    }

    /**
     * 签名自检探针 — POST /unipay/ping（走完整验签链路，一键判定商户号/应用/私钥/签名串是否可用）
     *
     * 对照契约 6.14 节（仅公共参数，无业务字段；公共字段由 [Client#execute] 注入，本仓约定参数即关联数组，故无参数对象）。
     * 与免签名 [Client#ping] 互补：本方法由持商户私钥方发起，非 0 业务码不抛异常而是原样返回，
     * 供调用方按 code 分类诊断（20052=验签失败且 msg 含服务端待签串；10408-10411=nonce/时钟；
     * 其余=商户号/应用类）；响应验签失败仍抛异常（平台公钥配置问题）。
     *
     * @param array<string,mixed> $param 请求参数（无业务字段，传 [] 即可；公共字段缺省自动注入）
     * @return array<string,mixed> NiuDunResult 关联数组；`data` 回显平台侧解析结果（供对接方核对商户身份与签名串构造）：
     *  mchNo string 商户号 / appId string 应用号 / appFromDefault bool 是否回落平台默认应用 /
     *  serverSignStr string 服务端待签串（与本地签名串比对可定位签名差异）
     */
    public function signedPing(array $param = []): array
    {
        return $this->execute('/unipay/ping', $param, false);
    }

    /**
     * 回调链路自检探针 — GET /unipay/callback/ping（免签名免登录，返回固定标识文本）
     *
     * 用于部署自检：探针可达即代表「通道回调」接口组已放行、后端地址配置正确。
     *
     * @return string 探针返回的标识文本（非 JSON）
     * @throws \RuntimeException 探针不可达/HTTP 非 200（旧平台版本可能无该路由）
     */
    public function ping(): string
    {
        $url = $this->config->getServiceUrl() . '/unipay/callback/ping';
        $opts = [
            'http' => [
                'method' => 'GET',
                'timeout' => $this->config->getTimeout() / 1000,
                'ignore_errors' => true,
            ],
        ];
        $context = stream_context_create($opts);
        $response = @file_get_contents($url, false, $context);
        // $http_response_header 是 file_get_contents **所在作用域**的魔术变量，必须在本方法内读取
        $headers = $http_response_header ?? [];
        if ($response === false) {
            throw new \RuntimeException('探针请求失败: 无法连接 ' . $url . self::streamErrorSuffix());
        }
        $code = self::statusFromHeaders($headers);
        if ($code !== 200) {
            throw new \RuntimeException('探针请求失败: HTTP ' . $code);
        }
        return $response;
    }

    /**
     * 回调验签（原始 HTTP body 字符串）— 对照契约第八节
     *
     * @param string $rawBody 平台异步通知的原始请求体（**未反序列化**，验签按字面量计算）
     * @return bool 验签是否通过（无 sign 字段、公钥未配置或格式非法均返回 false）
     */
    public function verifyNotice(string $rawBody): bool
    {
        $obj = json_decode($rawBody, true, 512, \JSON_BIGINT_AS_STRING);
        if (!is_array($obj) || !isset($obj['sign'])) {
            return false;
        }
        return SignUtil::verify($rawBody, $obj['sign'], $this->config->getPublicKey());
    }

    /**
     * HTTP POST（用 stream context，零 curl 依赖）
     *
     * 先判 HTTP 状态再回调 observer（对照 Java 版：非 200 直接抛「请求失败: HTTP xxx」，
     * 不把网关/鉴权错误响应当作平台业务响应交给验签逻辑）
     */
    private function httpPost(string $url, string $body): string
    {
        $opts = [
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json; charset=utf-8\r\n",
                'content' => $body,
                'timeout' => $this->config->getTimeout() / 1000,
                'ignore_errors' => true,
            ],
        ];
        $context = stream_context_create($opts);
        $response = @file_get_contents($url, false, $context);
        // $http_response_header 是 file_get_contents **所在作用域**的魔术变量，必须在本方法内读取
        $headers = $http_response_header ?? [];
        if ($response === false) {
            // 连接失败：不能静默当作空响应返回（否则会被当成「平台返回空内容」误导排查）
            throw new \RuntimeException('请求失败: 无法连接 ' . $url . self::streamErrorSuffix());
        }
        $code = self::statusFromHeaders($headers);
        if ($code !== 200) {
            throw new \RuntimeException('请求失败: HTTP ' . $code);
        }
        return $response;
    }

    /**
     * 从响应头里取 HTTP 状态码（取最后一条状态行，兼容 3xx 跳转后多段响应头）
     *
     * @param string[] $headers file_get_contents 的 $http_response_header 魔术变量
     */
    private static function statusFromHeaders(array $headers): int
    {
        $status = 200;
        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $header, $m)) {
                $status = (int) $m[1];
            }
        }
        return $status;
    }

    /**
     * 连接失败时的补充说明（stream 的最近一次错误，便于区分「地址写错」「服务未启动」「DNS 解析失败」）
     */
    private static function streamErrorSuffix(): string
    {
        $error = error_get_last();
        if (is_array($error) && isset($error['message']) && $error['message'] !== '') {
            return '（' . $error['message'] . '）';
        }
        return '';
    }

    /**
     * 当前时间的 GMT+8 字面量（yyyy-MM-dd HH:mm:ss）
     */
    private function nowGmt8(): string
    {
        return gmdate('Y-m-d H:i:s', time() + 8 * 3600);
    }

    /**
     * 生成请求号（UUID v4 字面量）
     */
    private function generateReqId(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /**
     * 生成随机串（nonceStr）
     */
    private function generateNonce(): string
    {
        return bin2hex(random_bytes(16));
    }
}
