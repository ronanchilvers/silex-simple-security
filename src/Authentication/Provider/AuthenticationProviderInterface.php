<?php

namespace App\Security\Authentication\Provider;

use App\Security\Request\RequestInterface;

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
     * @param App\Security\RequestInterface
     * @return App\Security\RequestInterface
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function authenticate(RequestInterface $token);

    /**
     * Does this provider support a given token
     *
     * @param App\Security\RequestInterface
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function supports(RequestInterface $token);
}
