<?php

namespace App\Security\Middleware;

use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

/**
 * Standard interface for middleware objects
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface MiddlewareInterface
{
    /**
     * Handle a request
     *
     * @param Symfony\Component\HttpFoundation\Request $request
     * @param Silex\Application $app
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function handle(Request $request, Application $app);
}
