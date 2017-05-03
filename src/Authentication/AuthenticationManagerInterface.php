<?php

namespace Ronanchilvers\Silex\Security\Authentication;

use Ronanchilvers\Silex\Security\Authentication\Provider\AuthenticationProviderInterface;
use Ronanchilvers\Silex\Security\Token\TokenInterface;
use Ronanchilvers\Silex\Security\Request\RequestInterface;
use Exception;

interface AuthenticationManagerInterface
{
    /**
     * Register an authentication provider with the manager
     *
     * @param Ronanchilvers\Silex\Security\Authentication\Provider\AuthenticationProviderInterface
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
     * @param Ronanchilvers\Silex\Security\RequestInterface $token
     * @return Ronanchilvers\Silex\Security\Token\TokenInterface
     * @throws Ronanchilvers\Silex\Security\Exception\AuthenticationException
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
