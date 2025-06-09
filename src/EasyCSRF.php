<?php

namespace EasyCSRF;

use EasyCSRF\Exceptions\InvalidCsrfTokenException;
use EasyCSRF\Interfaces\SessionProvider;

class EasyCSRF
{
    /**
     * @var SessionProvider
     */
    protected $session;

    /**
     * @var string
     */
    protected $sessionPrefix = 'easycsrf_';

    /**
     * @var bool
     */
    protected $ipCheck;

    /**
     * @param SessionProvider $sessionProvider
     * @param bool $ipCheck
     */
    public function __construct(SessionProvider $sessionProvider, $ipCheck = true)
    {
        $this->session = $sessionProvider;
        $this->ipCheck = $ipCheck;
    }

    /**
     * Generate a CSRF token.
     *
     * @param  string $key Key for this token
     * @return string
     * @throws \Exception
     */
    public function generate($key)
    {
        $key = $this->sanitizeKey($key);

        $token = $this->createToken();

        $this->session->set($this->sessionPrefix . $key, $token);

        return $token;
    }

    /**
     * Check the CSRF token is valid.
     *
     * @param  string  $key            Key for this token
     * @param  string  $token          The token string (usually found in $_POST)
     * @param  int|null     $timespan       Makes the token expire after $timespan seconds (null = never)
     * @param  boolean $multiple       Makes the token reusable and not one-time (Useful for ajax-heavy requests)
     * @throws InvalidCsrfTokenException
     * @throws \Exception
     */
    public function check($key, $token, $timespan = null, $multiple = false)
    {
        $key = $this->sanitizeKey($key);

        if (!$token) {
            throw new InvalidCsrfTokenException('CSRF token is missing');
        }

        $sessionToken = $this->session->get($this->sessionPrefix . $key);
        if (!$sessionToken) {
            throw new InvalidCsrfTokenException('Invalid CSRF session token');
        }

        if (!$multiple) {
            $this->session->set($this->sessionPrefix . $key, null);
        }

        if ($this->referralHash() !== substr(base64_decode($sessionToken), 10, 40)) {
            throw new InvalidCsrfTokenException('Invalid CSRF token');
        }

        if ($token !== $sessionToken) {
            throw new InvalidCsrfTokenException('Invalid CSRF token');
        }

        // Check for token expiration
        if (is_int($timespan) && (intval(substr(base64_decode($sessionToken), 0, 10)) + $timespan) < time()) {
            throw new InvalidCsrfTokenException('CSRF token has expired');
        }
    }

    /**
     * Sanitize the session key.
     *
     * @param string $key
     * @return string
     */
    protected function sanitizeKey($key)
    {
        return preg_replace('/[^a-zA-Z0-9]+/', '', $key);
    }

    /**
     * Create a new token.
     *
     * @return string
     * @throws \Exception
     */
    protected function createToken()
    {
        // time() is used for token expiration
        return base64_encode(time() . $this->referralHash() . $this->randomString());
    }

    /**
     * Get a session-specific secret.
     * If one is not $this->sessionPrefixwill be generated and stored in the session.
     *
     * @return string
     * @throws \Exception
     */
    protected function getSessionSecret()
    {
        $secretKey = $this->sessionPrefix . 'secret';
        $secret = $this->session->get($secretKey);

        if ($secret === null) {
            $secret = bin2hex(random_bytes(32));
            $this->session->set($secretKey, $secret);
        }

        return $secret;
    }

    /**
     * Return a unique referral hash.
     *
     * @return string
     * @throws \Exception
     */
    protected function referralHash()
    {
        if ($this->ipCheck) {
            if (empty($_SERVER['HTTP_USER_AGENT'])) {
                return sha1($_SERVER['REMOTE_ADDR']);
            }

            return sha1($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
        }

        return sha1($this->getSessionSecret());
    }

    /**
     * Generate a random string.
     *
     * @return string
     * @throws \Exception
     */
    protected function randomString(): string
    {
        return sha1(random_bytes(32));
    }
}
