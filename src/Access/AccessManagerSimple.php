<?php

namespace Ronanchilvers\Silex\Security\Access;

use Ronanchilvers\Silex\Security\Access\AccessManagerInterface;
use Ronanchilvers\Silex\Security\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Standard access manager
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class AccessManagerSimple implements AccessManagerInterface
{
    /**
     * @var string[]
     */
    protected $publicPaths = [];

    /**
     * Add a public path to the manager
     *
     * @param string $path
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function addPublicPath($path)
    {
        $this->publicPaths[$path] = $path;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAllowed(TokenInterface $token, Request $request)
    {
        if ($token->isAuthenticated()) {
            return true;
        }
        $uri = $request->getPathInfo();

        return in_array($uri, $this->publicPaths);
    }
}
