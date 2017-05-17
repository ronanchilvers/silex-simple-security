<?php

namespace Ronanchilvers\Silex\Security;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Ronanchilvers\Silex\Security\Authentication\AuthenticationManager;
use Ronanchilvers\Silex\Security\Authentication\Provider\UsernamePasswordProvider;
use Ronanchilvers\Silex\Security\DataCollector\SecurityDataCollector;
use Ronanchilvers\Silex\Security\Encoder\PasswordHashEncoder;
use Ronanchilvers\Silex\Security\Exception\ConfigurationException;
use Ronanchilvers\Silex\Security\Middleware\LogoutMiddleware;
use Ronanchilvers\Silex\Security\Middleware\UsernamePasswordMiddleware;
use Ronanchilvers\Silex\Security\Security;
use Ronanchilvers\Silex\Security\Token\Storage\SessionStorage;
use Ronanchilvers\Silex\Security\Twig\SecurityExtension;
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
                return new SecurityDataCollector(
                    $app['security.token.storage'],
                    $app['security.access.manager'],
                    $app['security.logout.path']
                );
            };

            return $collectors;
        });
        $app['twig.loader.filesystem']->addPath(
            __DIR__ . '/../resources/views',
            'Security'
        );
        $app->extend('data_collector.templates', function ($templates) {
            $templates[] = array('security', '@Security/security.html.twig');

            return $templates;
        });
        $app->extend('security.access.manager', function ($accessManager, $container) {
            $accessManager->matchPath(
                '^/_profiler',
                null,
                Security::SCOPE_ALL
            );

            return $accessManager;
        });
    }
}
