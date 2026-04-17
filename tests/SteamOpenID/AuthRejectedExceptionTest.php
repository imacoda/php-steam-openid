<?php

declare(strict_types=1);

namespace SteamOpenID;

use PHPUnit\Framework\TestCase;

class AuthRejectedExceptionTest extends TestCase
{
    public function testExposesRawResponse(): void
    {
        $response = "ns:http://specs.openid.net/auth/2.0\nis_valid:false\n";
        $exception = new AuthRejectedException('rejected', $response);

        $this->assertSame('rejected', $exception->getMessage());
        $this->assertSame($response, $exception->getResponse());
    }
}
