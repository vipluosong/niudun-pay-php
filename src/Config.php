<?php
declare(strict_types=1);

namespace NiuDun\OpenSdk;

/**
 * SDK 配置 — 对照 sdk-contract.md 第十节
 */
class Config
{
    /** @var string 网关地址（自动去尾斜杠） */
    private string $serviceUrl;
    /** @var string 商户号 */
    private string $mchNo;
    /** @var string|null 应用号（可选） */
    private ?string $appId = null;
    /** @var string 商户私钥 PEM（PKCS#8） */
    private string $privateKey;
    /** @var string 平台公钥 PEM（X.509） */
    private string $publicKey;
    /** @var int 请求超时（毫秒） */
    private int $timeout = 30000;

    public function getServiceUrl(): string
    {
        return rtrim($this->serviceUrl, '/');
    }

    public function setServiceUrl(string $serviceUrl): self
    {
        $this->serviceUrl = $serviceUrl;
        return $this;
    }

    public function getMchNo(): string
    {
        return $this->mchNo;
    }

    public function setMchNo(string $mchNo): self
    {
        $this->mchNo = $mchNo;
        return $this;
    }

    public function getAppId(): ?string
    {
        return $this->appId;
    }

    public function setAppId(?string $appId): self
    {
        $this->appId = $appId;
        return $this;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function setPrivateKey(string $privateKey): self
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function setPublicKey(string $publicKey): self
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function setTimeout(int $timeout): self
    {
        $this->timeout = $timeout;
        return $this;
    }
}
