<?php
declare(strict_types=1);

/**
 * demo 自举：注册 PSR-4 自动加载（demo 服务不依赖 composer 的 vendor/ 目录，直接源码可用）
 * 规则与 composer.json 的 autoload 一致：NiuDun\OpenSdk\ → 仓根 src/
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'NiuDun\\OpenSdk\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = dirname(__DIR__) . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
