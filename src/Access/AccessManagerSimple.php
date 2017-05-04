<?php

namespace Ronanchilvers\Silex\Security\Access;

use Ronanchilvers\Silex\Security\Access\AccessManagerInterface;
use Ronanchilvers\Silex\Security\Security;
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
    protected $paths = [];

    /**
     * Add a public path to the manager
     *
     * The first parameter here is a regex to match against the path. The second
     * is an optional HTTP method (or array of methods) to match. The third
     * parameter is an array of the scopes that should match the request - by
     * default anonymous scope is used.
     *
     * @param string $regex
     * @param null|string|string[] $method
     * @param string|string[] $scopes
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function matchPath(
        $regex,
        $methods = null,
        $scopes = Security::SCOPE_ALL
    ) {
        if (is_string($methods)) {
            $methods = [$methods];
        }
        if (is_string($scopes)) {
            $scopes = [$scopes];
        }
        $this->paths[$regex] = [
            'regex' => "#{$regex}#",
            'methods' => $methods,
            'scopes' => $scopes
        ];
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAllowed(TokenInterface $token, Request $request)
    {
        $uri = $request->getPathInfo();
        $method = $request->getMethod();
        $scope = $token->getScope();
        foreach ($this->paths as $data) {
            if (!in_array($scope, $data['scopes']) &&
                !in_array(Security::SCOPE_ALL, $data['scopes'])
            ) {
                continue;
            }
            if (0 == preg_match($data['regex'], $uri)) {
                continue;
            }
            if (!is_array($data['methods'])) {
                return true;
            }
            if (in_array($method, $data['methods'])) {
                return true;
            }
        }

        return false;
    }
}
