<?php

use PHPUnit\Framework\TestCase;
use EasyCSRF\EasyCSRF;
use EasyCSRF\Exceptions\InvalidCsrfTokenException;
use EasyCSRF\NativeSessionProvider;

class EasyCSRFTest extends TestCase
{
    protected $easyCSRF;

    protected function setUp(): void
    {
        $sessionProvider = new NativeSessionProvider();
        $this->easyCSRF = new EasyCSRF($sessionProvider);
    }

    public function testGenerate()
    {
        $token = $this->easyCSRF->generate('test');

        $this->assertNotNull($token);
    }

    public function testCheck()
    {
        $token = $this->easyCSRF->generate('test');
        $this->easyCSRF->check('test', $token);

        $this->assertNull($_SESSION['easycsrf_test']);
    }

    public function testCheckMultiple()
    {
        $token = $this->easyCSRF->generate('test');
        $this->easyCSRF->check('test', $token, null, true);

        $this->assertNotNull($_SESSION['easycsrf_test']);
    }

    public function testExceptionMissingFormToken()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $this->easyCSRF->check('test', '');
    }

    public function testExceptionMissingSessionToken()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $this->easyCSRF->check('test', '12345');
    }

    public function testExceptionInvalidToken()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $this->easyCSRF->generate('test');
        $this->easyCSRF->check('test', '12345');
    }

    public function testExceptionExpired()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $token = $this->easyCSRF->generate('test');
        sleep(2);
        $this->easyCSRF->check('test', $token, 1);
    }
}
