<?php

namespace Ronanchilvers\Silex\Security\Authentication\Provider;

use Ronanchilvers\Silex\Security\Request\RequestInterface;

/**
 * Interface for authentication providers
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface AuthenticationProviderInterface
{
    /**
     * Authenticate a token
     *
     * @param Ronanchilvers\Silex\Security\RequestInterface
     * @return Ronanchilvers\Silex\Security\RequestInterface
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function authenticate(RequestInterface $token);

    /**
     * Does this provider support a given token
     *
     * @param Ronanchilvers\Silex\Security\RequestInterface
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function supports(RequestInterface $token);
}
