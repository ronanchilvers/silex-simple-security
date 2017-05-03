<?php

namespace App\Security\Encoder;

/**
 * Interface for encoder objects
 *
 * NB: The salt parameters are not required. Some implementations don't need
 * them as salts are generated automatically.
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface EncoderInterface
{
    /**
     * Encode a given password
     *
     * @param string $password
     * @param string $salt
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function encode($password, $salt = null);

    /**
     * Verify a password against a hash
     *
     * @param string $hash
     * @param string $password
     * @param string $salt
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function verify($hash, $password, $salt = null);
}
