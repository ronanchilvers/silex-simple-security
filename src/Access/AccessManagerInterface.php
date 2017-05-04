<?php

namespace Ronanchilvers\Silex\Security\Access;

use Ronanchilvers\Silex\Security\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Standard interface for access managers
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface AccessManagerInterface
{
    /**
     * Is access allowed to a given uri for a given token
     *
     * @param Ronanchilvers\Silex\Security\Token\TokenInterface $token
     * @param Symfony\Component\HttpFoundation\Request $request
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAllowed(TokenInterface $token, Request $request);
}
