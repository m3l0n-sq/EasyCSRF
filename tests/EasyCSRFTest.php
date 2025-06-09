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
        $_SERVER['REMOTE_ADDR'] = '1.1.1.1';
        $_SERVER['HTTP_USER_AGENT'] = 'useragent';

        $sessionProvider = new NativeSessionProvider();
        $this->easyCSRF = new EasyCSRF($sessionProvider, false);
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

    public function testExceptionOrigin()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $sessionProvider = new NativeSessionProvider();
        $easyCSRF = new EasyCSRF($sessionProvider, true);

        $token = $easyCSRF->generate('test');
        $_SERVER['REMOTE_ADDR'] = '2.2.2.2';
        $easyCSRF->check('test', $token);
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

    public function testDefaultIsIpCheck()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $sessionProvider = new NativeSessionProvider();
        $easyCSRF = new EasyCSRF($sessionProvider);

        $token = $easyCSRF->generate('test_default_ip');
        $_SERVER['REMOTE_ADDR'] = '2.2.2.2';
        $easyCSRF->check('test_default_ip', $token);
    }

    public function testIpCheckMismatch()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $sessionProvider = new NativeSessionProvider();
        $easyCSRFWithIpCheck = new EasyCSRF($sessionProvider, true);
        $easyCSRFWithoutIpCheck = new EasyCSRF($sessionProvider, false);

        // Generate with IP check, validate without
        $token = $easyCSRFWithIpCheck->generate('test_ip_mismatch_1');
        $easyCSRFWithoutIpCheck->check('test_ip_mismatch_1', $token);
    }

    public function testNoIpCheckMismatch()
    {
        $this->expectException(InvalidCsrfTokenException::class);

        $sessionProvider = new NativeSessionProvider();
        $easyCSRFWithIpCheck = new EasyCSRF($sessionProvider, true);
        $easyCSRFWithoutIpCheck = new EasyCSRF($sessionProvider, false);

        // Generate without IP check, validate with
        $token = $easyCSRFWithoutIpCheck->generate('test_ip_mismatch_2');
        $easyCSRFWithIpCheck->check('test_ip_mismatch_2', $token);
    }
}
