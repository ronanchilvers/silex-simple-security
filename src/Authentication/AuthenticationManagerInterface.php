<?php

namespace App\Security\Authentication;

use App\Security\Authentication\Provider\AuthenticationProviderInterface;
use App\Security\Token\TokenInterface;
use App\Security\Request\RequestInterface;
use Exception;

interface AuthenticationManagerInterface
{
    /**
     * Register an authentication provider with the manager
     *
     * @param App\Security\Authentication\Provider\AuthenticationProviderInterface
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function registerProvider(AuthenticationProviderInterface $provider);

    /**
     * Does the manager have a particular provider already?
     *
     * @param string $providerClass
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function hasProvider($providerClass);

    /**
     * Authenticate a given token
     *
     * @param App\Security\RequestInterface $token
     * @return App\Security\Token\TokenInterface
     * @throws App\Security\Exception\AuthenticationException
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function authenticate(RequestInterface $token);

    /**
     * Get the last exception that happened during authentication
     *
     * @return \Exception
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getLastException();
}
