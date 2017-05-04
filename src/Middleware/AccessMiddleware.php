<?php

namespace Ronanchilvers\Silex\Security\Middleware;

use Ronanchilvers\Silex\Security\Access\AccessManagerInterface;
use Ronanchilvers\Silex\Security\Middleware\MiddlewareInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class AccessMiddleware implements MiddlewareInterface
{
    /**
     * @var Ronanchilvers\Silex\Security\Access\AccessManagerInterface
     */
    protected $accessManager;

    /**
     * Class constructor
     *
     * @param Ronanchilvers\Silex\Security\Access\AccessManagerInterface $accessManager
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(AccessManagerInterface $accessManager)
    {
        $this->accessManager = $accessManager;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function handle(Request $request, Application $app)
    {
        if (!$this->accessManager->isAllowed(
                $app['token'],
                $request
            )
        ) {
            $path = $app['security.denied.path'] ?: $app['security.login.path'] ;
            return $app->redirect($path);
        }
    }
}
