<?php

namespace Ronanchilvers\Silex\Security\Encoder;

use Ronanchilvers\Silex\Security\Encoder\EncoderInterface;

/**
 * Password encoder using the standard password hashing functions in php 5.5+
 *
 * NB: Salt is not needed or used in this implementation.
 *
 * @see http://php.net/manual/en/book.password.php
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class PasswordHashEncoder implements EncoderInterface
{
    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function encode($password, $salt = null)
    {
        return password_hash(
            $password,
            PASSWORD_DEFAULT
        );
    }

    /**
     * Verify a password against a hash
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function verify($hash, $password, $salt = null)
    {
        return password_verify(
            $password,
            $hash
        );
    }
}
