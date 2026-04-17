<?php

declare(strict_types=1);

namespace SteamOpenID;

use RuntimeException;

/**
 * Thrown when Steam accepted the `check_authentication` call and responded with
 * HTTP 2xx, but the response did not contain `is_valid:true` — meaning the
 * OpenID nonce/signature was rejected (expired, reused, tampered, etc.).
 *
 * Retrying is pointless: the nonce is single-use and Steam has already
 * recorded the verdict. A fresh OpenID handshake must be initiated.
 */
class AuthRejectedException extends RuntimeException
{
    private string $response;

    public function __construct(string $message, string $response)
    {
        parent::__construct($message);
        $this->response = $response;
    }

    public function getResponse(): string
    {
        return $this->response;
    }
}
