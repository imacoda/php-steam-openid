<?php

declare(strict_types=1);

namespace SteamOpenID;

use PHPUnit\Framework\TestCase;

class TransientExceptionTest extends TestCase
{
    public function testExposesHttpCodeAndCurlError(): void
    {
        $exception = new TransientException('boom', 503, 'Operation timed out');

        $this->assertSame('boom', $exception->getMessage());
        $this->assertSame(503, $exception->getHttpCode());
        $this->assertSame('Operation timed out', $exception->getCurlError());
    }

    public function testCanRepresentCurlFailureWithoutHttpCode(): void
    {
        $exception = new TransientException('connect failed', 0, 'Could not resolve host');

        $this->assertSame(0, $exception->getHttpCode());
        $this->assertSame('Could not resolve host', $exception->getCurlError());
    }
}
