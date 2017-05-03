<?php

namespace App\Security;

use App\Security\Authentication\AuthenticationManager;
use App\Security\Authentication\Provider\UsernamePasswordProvider;
use App\Security\DataCollector\SecurityDataCollector;
use App\Security\Encoder\PasswordHashEncoder;
use App\Security\Exception\ConfigurationException;
use App\Security\Middleware\LogoutMiddleware;
use App\Security\Middleware\UsernamePasswordMiddleware;
use App\Security\Token\Storage\SessionStorage;
use App\Security\Twig\SecurityExtension;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\BootableProviderInterface;
use Silex\Application;
use Silex\Route;

class SecurityWebProfilerProvider implements ServiceProviderInterface
{

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function register(Container $app)
    {
        $app['data_collectors'] = $app->extend('data_collectors', function($collectors, $app) {
            $collectors['security'] = function ($app) {
                return new SecurityDataCollector($app['security.token.storage']);
            };

            return $collectors;
        });
        $app['twig.loader.filesystem']->addPath(
            __DIR__ . '/Resources/views',
            'Security'
        );
        $app->extend('data_collector.templates', function ($templates) {
            $templates[] = array('security', '@Security/security.html.twig');

            return $templates;
        });
    }
}
