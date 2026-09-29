<?php
declare(strict_types=1);

/**
 * 牛盾支付 PHP SDK 联调 Demo — 单文件路由
 *
 * 启动（仓根执行）：php -S 127.0.0.1:9793 demo/router.php
 *
 * php -S 的内置服务器把**全部请求**都交给本文件，因此由它分发所有路由；
 * 所有交易调用都经 Client 走 SDK 真实调用链（签名 / 请求 / 验签），同时验证 SDK 与平台 unipay 接口两侧：
 *
 * - `GET /`、`/index.html` 调试页（readfile 直接输出 demo/index.html）
 * - `GET|POST /demo/config` 连接配置：页面弹窗内填写服务地址/商户号/密钥，配置只存内存**不落盘**
 * - `POST /demo/ping` 连通性自检：服务端代调 `GET /unipay/callback/ping` 探针（浏览器直连平台会跨域）
 * - `POST /demo/signed-ping` 签名链路自检：服务端代调 `POST /unipay/ping` 签名探针（「测试连接」第二段，
 *   判定当前配置的商户号/应用/商户私钥是否正确、能否发起真实调用）
 * - `POST /demo/{action}` 调 SDK 发起真实请求，回显「签名后请求体 + 平台原始响应 + 响应验签结果」；
 *   支持全部 15 个开放接口，action 取值见 ACTIONS 表
 * - `POST /callback/{pay|refund|transfer|alloc}`（含通用 `/callback`）接收平台异步通知，用平台公钥验签后暂存
 * - `GET /demo/callbacks` 回调记录（页面轮询）；`POST /demo/callbacks/clear` 清空
 *
 * 零新增依赖：HTTP 层直接用 PHP 内置 `php -S`，不引入任何 Web 框架；不在 composer 环境下也能跑（bootstrap.php 自带 PSR-4 加载）。
 */

// ------------------------------------------------------------------
// 自举：优先用 composer 的 autoloader（已 install 时），否则退回 demo 自带 PSR-4 加载
// ------------------------------------------------------------------
$vendorAutoload = dirname(__DIR__) . '/vendor/autoload.php';
if (is_file($vendorAutoload)) {
    require_once $vendorAutoload;
}
require_once __DIR__ . '/bootstrap.php';

use NiuDun\OpenSdk\Client;
use NiuDun\OpenSdk\Config;
use NiuDun\OpenSdk\Util\RsaUtil;
use NiuDun\OpenSdk\Util\SignUtil;

/** 调试页文件 */
const DEMO_PAGE = __DIR__ . '/index.html';
/** 监听端口（启动命令固定 9793；如需换端口改启动命令即可，本文件不解析 --port） */
const DEMO_PORT = 9793;
/** 回调记录保留上限（超出丢弃最老记录） */
const MAX_CALLBACKS = 200;

// ------------------------------------------------------------------
// 状态（连接配置 + 回调记录）
//
// 注意：php -S（cli-server）虽然只有一个进程，但**每个请求都是全新的执行上下文**——
// 用户态全局变量/静态变量不跨请求保留（实测同 PID 下自增计数恒为 1），
// 因此不能像 Java 版那样用全局内存字段保存配置与回调记录。
// 这里改落到一份进程外的临时状态文件：
//   - 优先 `/dev/shm`（Linux tmpfs＝内存盘，效果等同「只存内存」），回退系统临时目录；
//   - 文件权限收紧为 0600，只在本机、只在 php -S 进程存活期间有效；
//   - 状态里记录进程 PID，**进程重启后 PID 变化即视为全新会话**（语义与 Java 版「重启即回默认值」一致）；
//   - 可用环境变量 `NIUDUN_DEMO_STATE` 覆盖状态文件路径。
// 读写入口统一走 state() / statePersist()（见文件末尾「基础设施」）。
// ------------------------------------------------------------------

/**
 * action → SDK 方法映射表（15 个业务接口 + 签名自检探针），新增接口只需在此登记一行
 * 值同时承担两个用途：取值即「SDK 方法名 + 平台接口路径」，调用 `$client->{$method}($param)`
 */
const ACTIONS = [
    // 支付族
    'pay' => ['method' => 'pay', 'path' => '/unipay/pay'],
    'close' => ['method' => 'close', 'path' => '/unipay/close'],
    'query-pay-order' => ['method' => 'queryPayOrder', 'path' => '/unipay/query/pay-order'],
    'sync-pay-order' => ['method' => 'syncPayOrder', 'path' => '/unipay/sync/order/pay'],
    // 退款族
    'refund' => ['method' => 'refund', 'path' => '/unipay/refund'],
    'query-refund-order' => ['method' => 'queryRefundOrder', 'path' => '/unipay/query/refund-order'],
    'sync-refund-order' => ['method' => 'syncRefundOrder', 'path' => '/unipay/sync/order/refund'],
    // 转账族
    'transfer' => ['method' => 'transfer', 'path' => '/unipay/transfer'],
    'query-transfer-order' => ['method' => 'queryTransferOrder', 'path' => '/unipay/query/transfer-order'],
    'sync-transfer-order' => ['method' => 'syncTransferOrder', 'path' => '/unipay/sync/order/transfer'],
    // 分账族
    'alloc' => ['method' => 'alloc', 'path' => '/unipay/alloc'],
    'query-alloc-order' => ['method' => 'queryAllocOrder', 'path' => '/unipay/query/alloc-order'],
    'sync-alloc-order' => ['method' => 'syncAllocOrder', 'path' => '/unipay/sync/order/alloc'],
    // 网关族
    'gateway-pre-pay' => ['method' => 'gatewayPrePay', 'path' => '/unipay/gateway/pre-pay'],
    'gateway-query' => ['method' => 'gatewayQuery', 'path' => '/unipay/gateway/query'],
    // 自检族：探针非 0 码在 handleTrade 转成异常，与其它接口的失败回显路径一致（完整诊断走 /demo/signed-ping）
    'signed-ping' => ['method' => 'signedPing', 'path' => '/unipay/ping'],
];

// ------------------------------------------------------------------
// 路由分发
// ------------------------------------------------------------------

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if (!is_string($path) || $path === '') {
    $path = '/';
}

try {
    // 调试页
    if ($method === 'GET' && ($path === '/' || $path === '/index.html')) {
        if (!is_file(DEMO_PAGE)) {
            textOut('调试页缺失: ' . DEMO_PAGE, 500);
        }
        header('Content-Type: text/html; charset=utf-8');
        readfile(DEMO_PAGE);
        return true;
    }
    // 连接配置（配置存内存，服务端不落盘）
    if ($path === '/demo/config' && ($method === 'GET' || $method === 'POST')) {
        handleConfig($method);
        return true;
    }
    // 回调记录（须排在 /demo/* 交易路由之前匹配，否则会被当成交易 action）
    if ($method === 'GET' && $path === '/demo/callbacks') {
        $records = state()['callbacks'];
        jsonOut(['count' => count($records), 'records' => $records]);
        return true;
    }
    if ($method === 'POST' && $path === '/demo/callbacks/clear') {
        $st = state();
        $st['callbacks'] = [];
        statePersist($st);
        jsonOut(['ok' => true]);
        return true;
    }
    // 连通性自检：服务端代调平台探针（浏览器直连平台地址会跨域，故由本服务中转）
    if ($method === 'POST' && $path === '/demo/ping') {
        handlePing();
        return true;
    }
    // 签名链路自检：服务端代调签名自检探针 POST /unipay/ping（「测试连接」第二段，须排在 /demo/* 通配之前）
    if ($method === 'POST' && $path === '/demo/signed-ping') {
        handleSignedPing();
        return true;
    }
    // 交易调试（经 SDK 真实调用链）
    if ($method === 'POST' && strpos($path, '/demo/') === 0) {
        handleTrade(substr($path, strlen('/demo/')));
        return true;
    }
    // 平台异步通知接收端点（返回固定 SUCCESS，平台要求 HTTP 2xx 且 body 为 SUCCESS）
    if ($method === 'POST' && strpos($path, '/callback') === 0) {
        // 与 Java 版一致：/callback/pay → type=pay；裸 /callback → type=common
        handleCallback(ltrim(substr($path, strlen('/callback')), '/'));
        return true;
    }
    jsonOut(['error' => 'not found: ' . $path], 404);
    return true;
} catch (\Throwable $e) {
    jsonOut(['error' => $e->getMessage()], 500);
    return true;
}

// ------------------------------------------------------------------
// /demo/config 连接配置（页面内配置，服务端只存内存不落盘）
// ------------------------------------------------------------------

/**
 * @param string $method GET 读脱敏状态 / POST 保存配置
 */
function handleConfig(string $method): void
{
    if ($method === 'GET') {
        jsonOut(configInfo(state()['config']));
        return;
    }
    $body = jsonDecodeArray(readBody());
    $serviceUrl = trim((string) ($body['serviceUrl'] ?? ''));
    $mchNo = trim((string) ($body['mchNo'] ?? ''));
    if ($serviceUrl === '' || $mchNo === '') {
        jsonOut(['error' => '服务地址与商户号不能为空'], 400);
        return;
    }
    // 密钥字段语义（三态）：字段缺省=保持原值；空串=清空；非空=替换（先做 PEM 解析校验，即时反馈格式错误）
    $state = state();
    $current = $state['config'];
    $privateKey = $current['privateKey'];
    if (array_key_exists('privateKey', $body)) {
        $value = trim((string) $body['privateKey']);
        if ($value === '') {
            $privateKey = null;
        } else {
            if (!RsaUtil::isValidPrivateKey($value)) {
                jsonOut(['error' => '商户私钥无效: 需为 PKCS#8 格式的 RSA 私钥 PEM'], 400);
                return;
            }
            $privateKey = $value;
        }
    }
    $publicKey = $current['publicKey'];
    if (array_key_exists('publicKey', $body)) {
        $value = trim((string) $body['publicKey']);
        if ($value === '') {
            $publicKey = null;
        } else {
            if (!RsaUtil::isValidPublicKey($value)) {
                jsonOut(['error' => '平台公钥无效: 需为 X.509 格式的 RSA 公钥 PEM'], 400);
                return;
            }
            $publicKey = $value;
        }
    }
    // 整体替换配置快照（读方每次取最新）
    $state['config'] = [
        'serviceUrl' => $serviceUrl,
        'mchNo' => $mchNo,
        'appId' => trimOrNull((string) ($body['appId'] ?? '')),
        'privateKey' => $privateKey,
        'publicKey' => $publicKey,
    ];
    statePersist($state);
    error_log('[配置] 页面更新连接配置: ' . $serviceUrl . ' 商户 ' . $mchNo);
    jsonOut(configInfo($state['config']));
}

/**
 * 当前配置的脱敏状态（不返回密钥内容，仅返回是否已配置）
 *
 * @param array<string,mixed> $cfg 当前配置快照
 * @return array<string,mixed>
 */
function configInfo(array $cfg): array
{
    return [
        'serviceUrl' => rtrim((string) $cfg['serviceUrl'], '/'),
        'mchNo' => $cfg['mchNo'],
        'appId' => $cfg['appId'],
        'callbackBase' => callbackBase(),
        'privateKeySet' => $cfg['privateKey'] !== null && $cfg['privateKey'] !== '',
        'publicKeySet' => $cfg['publicKey'] !== null && $cfg['publicKey'] !== '',
    ];
}

// ------------------------------------------------------------------
// /demo/ping 连通性自检（服务端中转，规避浏览器跨域）
// ------------------------------------------------------------------

/**
 * 代调平台自检探针 `GET /unipay/callback/ping`，供页面「测试连接」按钮使用
 */
function handlePing(): void
{
    $cfg = state()['config'];
    $result = ['serviceUrl' => rtrim($cfg['serviceUrl'], '/')];
    $begin = microtime(true);
    try {
        $marker = (new Client(buildConfig($cfg)))->ping();
        $result['success'] = true;
        $result['marker'] = $marker;
        $result['durationMs'] = (int) round((microtime(true) - $begin) * 1000);
    } catch (\Throwable $e) {
        $result['success'] = false;
        $msg = $e->getMessage();
        // 401/404 是探针链路上最常见的两种情况，直接给出可操作的排查方向
        if (strpos($msg, 'HTTP 401') !== false || strpos($msg, 'HTTP 404') !== false) {
            $msg .= '（需平台版本包含部署自检探针 /unipay/callback/ping，且网关放行该前缀）';
        }
        $result['error'] = $msg;
        $result['durationMs'] = (int) round((microtime(true) - $begin) * 1000);
    }
    jsonOut($result);
}

// ------------------------------------------------------------------
// /demo/signed-ping 签名链路自检（服务端中转，规避浏览器跨域）
// ------------------------------------------------------------------

/**
 * 代调签名自检探针 `POST /unipay/ping`，供页面「测试连接」第二段使用：
 * 判定当前配置的商户号/应用/商户私钥/签名串构造是否正确、能否发起真实调用
 */
function handleSignedPing(): void
{
    $cfg = state()['config'];
    $result = ['serviceUrl' => rtrim((string) $cfg['serviceUrl'], '/')];
    $begin = microtime(true);
    $privateBlank = $cfg['privateKey'] === null || $cfg['privateKey'] === '';
    $publicBlank = $cfg['publicKey'] === null || $cfg['publicKey'] === '';
    if ($privateBlank || $publicBlank) {
        $result['success'] = false;
        $result['hint'] = $privateBlank
            ? '尚未配置商户私钥，请先在「连接配置」中填写'
            : '尚未配置平台公钥（响应无法验签），请先在「连接配置」中填写';
        jsonOut($result);
        return;
    }
    // observer 捕获发出报文与原始响应，供页面比对签名串（发出 JSON vs 服务端待签串）
    $captured = [null, null];
    $client = (new Client(buildConfig($cfg)))->setObserver(
        function (string $signedJson) use (&$captured): void {
            $captured[0] = $signedJson;
        },
        function (string $rawBody) use (&$captured): void {
            $captured[1] = $rawBody;
        }
    );
    try {
        $r = $client->signedPing();
        // 业务码按数值语义比较（字符串 "0" 同样视为成功；缺失/非数值按 -1 处理，与 Client#execute 同口径）
        $code = $r['code'] ?? -1;
        $code = is_numeric($code) ? (int) $code : -1;
        $result['success'] = $code === 0;
        $result['code'] = $code;
        $result['msg'] = $r['msg'] ?? '';
        $result['data'] = $r['data'] ?? null;
        if ($code !== 0) {
            $result['hint'] = classifyProbeError($code);
        }
    } catch (\Throwable $e) {
        // 走到异常只会是硬错误：网络不通 / HTTP 非 200 / 响应验签失败（平台公钥问题）
        $msg = $e->getMessage();
        $result['success'] = false;
        $result['error'] = $msg;
        if (strpos($msg, '响应验签失败') !== false) {
            $result['hint'] = '平台响应验签失败：请核对「连接配置」中的平台公钥';
        } elseif (strpos($msg, 'HTTP 404') !== false) {
            $result['hint'] = '网关未放行「商户开放 API」(/unipay) 接口组，需在部署面板开启';
        }
    } finally {
        $result['requestBody'] = $captured[0];
        $result['responseBody'] = $captured[1];
        $result['durationMs'] = (int) round((microtime(true) - $begin) * 1000);
    }
    jsonOut($result);
}

/**
 * 探针错误码分类提示（对照契约 6.14 诊断表）
 */
function classifyProbeError(int $code): string
{
    if ($code === 20052) {
        return '验签失败：商户私钥与平台上配置的公钥不配对，或签名串构造不一致——比对「发出报文」与响应 msg 中的服务端待签串';
    }
    if ($code === 10408 || $code === 10409) {
        return 'Nonce 防重放拦截：请勿复用请求（每次点击都会生成新 nonce）';
    }
    if ($code === 10410 || $code === 10411) {
        return '请求时间超窗：本机时钟偏差过大，或 reqTime 未按 GMT+8 yyyy-MM-dd HH:mm:ss 字面量';
    }
    return '商户号/应用类错误（code ' . $code . '）：核对 mchNo 与 appId 是否存在且启用';
}

// ------------------------------------------------------------------
// /demo/* 交易调试
// ------------------------------------------------------------------

/**
 * @param string $action 交易 action（ACTIONS 表的键）
 */
function handleTrade(string $action): void
{
    $param = jsonDecodeArray(readBody());

    // 配置快照（一次读取，保证单次调用内一致）
    $cfg = state()['config'];
    if ($cfg['privateKey'] === null || $cfg['privateKey'] === '') {
        jsonOut([
            'success' => false,
            'requestBody' => null,
            'responseBody' => null,
            'durationMs' => 0,
            'signVerified' => null,
            'result' => null,
            'error' => '尚未配置商户私钥，请点击右上角「连接配置」填写后重试',
        ]);
        return;
    }
    if (!isset(ACTIONS[$action])) {
        jsonOut(['error' => 'unknown action: ' . $action], 404);
        return;
    }

    // observer 捕获本次调用的请求体/响应体（每次调用独立实例，无共享状态）
    $captured = [null, null];
    $client = (new Client(buildConfig($cfg)))->setObserver(
        function (string $signedJson) use (&$captured): void {
            $captured[0] = $signedJson;
        },
        function (string $rawBody) use (&$captured): void {
            $captured[1] = $rawBody;
        }
    );

    $begin = microtime(true);
    $error = null;
    try {
        if ($action === 'signed-ping') {
            // 自检族：探针非 0 码在此转成异常，与其它接口的失败回显路径一致（完整诊断走 /demo/signed-ping）
            $r = $client->signedPing($param);
            $code = $r['code'] ?? -1;
            $code = is_numeric($code) ? (int) $code : -1;
            if ($code !== 0) {
                throw new \RuntimeException('[' . $code . '] ' . (string) ($r['msg'] ?? ''));
            }
        } else {
            $method = ACTIONS[$action]['method'];
            $client->{$method}($param);
        }
    } catch (\Throwable $e) {
        // SDK 抛出（业务失败/验签失败/网络异常）也属联调有效结果，回显给页面
        $error = $e->getMessage();
    }
    $durationMs = (int) round((microtime(true) - $begin) * 1000);

    // 组装统一回显结构：SDK 实际发出的签名请求 + 平台原始响应 + 解析结果 + 验签
    jsonOut([
        'success' => $error === null,
        'requestBody' => $captured[0],
        'responseBody' => $captured[1],
        'durationMs' => $durationMs,
        'signVerified' => verifyResponse($captured[1], $cfg),
        'result' => parseResult($captured[1]),
        'error' => $error,
    ]);
}

/**
 * 响应验签（demo 层独立复核，便于对照 SDK 内部验签行为）
 *
 * @param string|null $responseBody 平台原始响应体
 * @param array<string,mixed> $cfg 当前配置快照
 * @return bool|null true 验签通过 / false 验签失败 / **null 表示响应不带签名**（平台业务异常经全局异常处理器
 *                   返回 Result 形状，页面据此显示「未签名」而非「验签失败」）
 */
function verifyResponse(?string $responseBody, array $cfg): ?bool
{
    if ($responseBody === null || $responseBody === '') {
        return null;
    }
    $obj = json_decode($responseBody, true, 512, JSON_BIGINT_AS_STRING);
    if (!is_array($obj) || !isset($obj['sign']) || $obj['sign'] === '') {
        return null;
    }
    return RsaUtil::verify(
        SignUtil::buildSignStr($responseBody),
        $obj['sign'],
        (string) $cfg['publicKey']
    );
}

/**
 * 从原始响应解析 NiuDunResult 展示字段（业务失败时不抛异常，原样透出 code/msg）；解析失败给 {"parseError": 原文}
 *
 * @return array<string,mixed>|null
 */
function parseResult(?string $responseBody): ?array
{
    if ($responseBody === null || $responseBody === '') {
        return null;
    }
    $obj = json_decode($responseBody, true, 512, JSON_BIGINT_AS_STRING);
    if (!is_array($obj)) {
        return ['parseError' => $responseBody];
    }
    return $obj;
}

// ------------------------------------------------------------------
// /callback/* 异步通知接收
// ------------------------------------------------------------------

/**
 * @param string $type 回调类型（pay/refund/transfer/alloc，或空串表示通用 /callback）
 */
function handleCallback(string $type): void
{
    $body = readBody();
    $cfg = state()['config'];
    $record = [
        'time' => gmdate('Y-m-d H:i:s', time() + 8 * 3600),
        'type' => $type === '' ? 'common' : $type,
        'signVerified' => false,
        'code' => null,
        'msg' => null,
        'body' => $body,
    ];
    if ($cfg['publicKey'] === null || $cfg['publicKey'] === '') {
        $record['signVerified'] = false;
        $record['msg'] = '平台公钥未配置，无法验签（请在页面「连接配置」中补充）';
    } else {
        $obj = json_decode($body, true, 512, JSON_BIGINT_AS_STRING);
        if (!is_array($obj)) {
            $record['msg'] = '解析失败: 报文不是合法 JSON';
        } else {
            $record['signVerified'] = (new Client(buildConfig($cfg)))->verifyNotice($body);
            $record['code'] = $obj['code'] ?? null;
            $record['msg'] = $obj['msg'] ?? ($obj['message'] ?? null);
        }
    }
    // 新记录挂队首，超出上限丢最老
    $state = state();
    array_unshift($state['callbacks'], $record);
    if (count($state['callbacks']) > MAX_CALLBACKS) {
        array_splice($state['callbacks'], MAX_CALLBACKS);
    }
    statePersist($state);
    error_log('[回调] ' . $record['time'] . ' ' . $record['type']
        . ' 验签=' . ($record['signVerified'] ? 'true' : 'false'));
    // 平台要求 HTTP 2xx 且 body 等于 SUCCESS
    textOut('SUCCESS');
}

// ------------------------------------------------------------------
// 基础设施
// ------------------------------------------------------------------

// ------------------------------------------------------------------
// 状态存储（连接配置 + 回调记录）
//
// 见文件头部说明：php -S 每个请求都是全新执行上下文，状态必须放进程外。
// 规则：
//   - state() 每次请求读一次（状态里 PID 与服务进程不一致＝服务已重启，回到默认值）；
//   - statePersist() 在配置保存 / 回调入队 / 回调清空时整份覆盖写入；
//   - php -S 单线程串行处理，无并发写竞争，无需加锁。
// ------------------------------------------------------------------

/**
 * 状态文件路径：环境变量 NIUDUN_DEMO_STATE 优先；否则 /dev/shm（Linux tmpfs＝内存盘）→ 系统临时目录
 */
function stateFile(): string
{
    $override = getenv('NIUDUN_DEMO_STATE');
    if (is_string($override) && $override !== '') {
        return $override;
    }
    $name = 'niudun-demo-php-' . (string) ($_SERVER['SERVER_PORT'] ?? DEMO_PORT) . '.json';
    if (is_dir('/dev/shm') && is_writable('/dev/shm')) {
        return '/dev/shm/' . $name;
    }
    return sys_get_temp_dir() . DIRECTORY_SEPARATOR . $name;
}

/**
 * 默认状态（服务地址取本地 9999，密钥留空待页面填写）
 *
 * @return array<string,mixed>
 */
function defaultState(): array
{
    return [
        'config' => [
            'serviceUrl' => 'http://127.0.0.1:9999',
            'mchNo' => '',
            'appId' => null,
            'privateKey' => null,
            'publicKey' => null,
        ],
        'callbacks' => [],
    ];
}

/**
 * 读取状态（单请求内复用；服务重启后 PID 不匹配即回到默认值，并清掉上一进程留下的状态文件）
 *
 * @return array<string,mixed>
 */
function state(): array
{
    static $state = null;
    if ($state !== null) {
        return $state;
    }
    $file = stateFile();
    $raw = is_file($file) ? @file_get_contents($file) : false;
    $data = is_string($raw) ? json_decode($raw, true, 512, JSON_BIGINT_AS_STRING) : null;
    if (is_array($data) && ($data['pid'] ?? null) === getmypid() && isset($data['config']) && is_array($data['config'])) {
        $state = [
            'config' => $data['config'] + defaultState()['config'],
            'callbacks' => is_array($data['callbacks'] ?? null) ? $data['callbacks'] : [],
        ];
        return $state;
    }
    if (is_file($file)) {
        @unlink($file);
    }
    $state = defaultState();
    return $state;
}

/**
 * 整份覆盖写入状态（内容含密钥，文件权限收紧为仅属主可读写 0600）
 *
 * @param array<string,mixed> $state
 */
function statePersist(array $state): void
{
    $file = stateFile();
    $state['pid'] = getmypid();
    $json = json_encode($state, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    if ($json === false) {
        error_log('[状态] 状态序列化失败，本次不落状态文件');
        return;
    }
    $oldUmask = umask(0077);
    $written = @file_put_contents($file, $json);
    umask($oldUmask);
    if ($written === false) {
        error_log('[状态] 状态写入失败: ' . $file);
        return;
    }
    @chmod($file, 0600);
}

// ------------------------------------------------------------------
// 其它工具
// ------------------------------------------------------------------

/**
 * 由配置数组构建 Config 实例
 *
 * @param array<string,mixed> $cfg
 */
function buildConfig(array $cfg): Config
{
    return (new Config())
        ->setServiceUrl((string) $cfg['serviceUrl'])
        ->setMchNo((string) $cfg['mchNo'])
        ->setAppId($cfg['appId'] === null ? null : (string) $cfg['appId'])
        ->setPrivateKey((string) $cfg['privateKey'])
        ->setPublicKey((string) $cfg['publicKey']);
}

/**
 * 对外可达的回调基址（页面把 notifyUrl 的 `@callbackBase/...` 默认值展开成完整 URL 用）
 */
function callbackBase(): string
{
    $host = $_SERVER['HTTP_HOST'] ?? ('127.0.0.1:' . DEMO_PORT);
    return 'http://' . $host;
}

/**
 * 读取请求体（二进制安全）
 */
function readBody(): string
{
    $body = file_get_contents('php://input');
    return $body === false ? '' : $body;
}

/**
 * JSON 请求体解析为关联数组（空体/非法 JSON 一律给空数组，按字段缺省处理）
 *
 * @return array<string,mixed>
 */
function jsonDecodeArray(string $body): array
{
    $obj = json_decode($body, true, 512, JSON_BIGINT_AS_STRING);
    return is_array($obj) ? $obj : [];
}

/**
 * 去空白；空串返回 null
 */
function trimOrNull(string $value): ?string
{
    $value = trim($value);
    return $value === '' ? null : $value;
}

/**
 * 输出 JSON（允许非 ASCII 原样输出，金额保持整数不转浮点）
 *
 * @param mixed $payload
 */
function jsonOut($payload, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    echo $json === false ? '{"error":"响应序列化失败"}' : $json;
}

/**
 * 输出纯文本（回调应答固定 SUCCESS）
 */
function textOut(string $text, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    echo $text;
}
