<?php

namespace App\Security\Middleware;

use App\Security\Middleware\MiddlewareInterface;
use App\Security\Request\UsernamePasswordRequest;
use Silex\Application;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouteCollection;

/**
 * Route middleware for username + password authentication
 *
 * @author me
 */
class UsernamePasswordMiddleware implements MiddlewareInterface
{
    /**
     * Method to run this middleware
     *
     * @param Symfony\Component\HttpFoundation\Request $request
     * @param Silex\Application $app
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function handle(Request $request, Application $app)
    {
        if ($app['security.check.path'] !== $request->getPathInfo()) {
            return;
        }

        try {
            $key = $app['security.auth.manager']->authenticate(
                new UsernamePasswordRequest(
                    $request->request->get('security_username'),
                    $request->request->get('security_password')
                )
            );

            return $app->redirect(
                $app['security.home.path']
            );
        } catch (\Exception $ex) {
            return $app->redirect(
                $app['security.login.path']
            );
        }
    }
}
