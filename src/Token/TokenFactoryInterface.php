<?php

namespace Ronanchilvers\Silex\Security\Token;

use Ronanchilvers\Silex\Security\Token\TokenInterface;

/**
 * Standard interface for security token factories
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface TokenFactoryInterface
{
    /**
     * Get a token for a given token class
     *
     * @param string $class
     * @return Ronanchilvers\Silex\Security\Token\TokenInterface
     * @throws RuntimeException If an invalid token class is requested
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function factory($class);

    /**
     * Validate a token
     *
     * @param Ronanchilvers\Silex\Security\Token\TokenInterface
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function validate(TokenInterface $token);
}
