<?php

namespace Ronanchilvers\Silex\Security\Middleware;

use Ronanchilvers\Silex\Security\Middleware\MiddlewareInterface;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class LogoutMiddleware implements MiddlewareInterface
{
    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function handle(Request $request, Application $app)
    {
        if ($app['security.logout.path'] != $request->getPathInfo()) {
            return;
        }
        $storage = $app['security.token.storage'];
        $storage->eraseToken();
    }
}
