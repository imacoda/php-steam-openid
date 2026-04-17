<?php

declare(strict_types=1);

namespace SteamOpenID;

use RuntimeException;

/**
 * Thrown when the `check_authentication` call to Steam fails due to a transient
 * upstream issue (network error, connect/read timeout, empty body, HTTP 5xx, or
 * non-2xx status that is not a deliberate rejection).
 *
 * Callers may safely retry with a new OpenID callback — the Steam nonce was not
 * consumed, because Steam never delivered a usable response.
 */
class TransientException extends RuntimeException
{
    private int $httpCode;
    private string $curlError;

    public function __construct(string $message, int $httpCode, string $curlError)
    {
        parent::__construct($message);
        $this->httpCode = $httpCode;
        $this->curlError = $curlError;
    }

    public function getHttpCode(): int
    {
        return $this->httpCode;
    }

    public function getCurlError(): string
    {
        return $this->curlError;
    }
}
