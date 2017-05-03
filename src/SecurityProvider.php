<?php

namespace Ronanchilvers\Silex\Security;

use Ronanchilvers\Silex\Security\Authentication\AuthenticationManager;
use Ronanchilvers\Silex\Security\Authentication\Provider\UsernamePasswordProvider;
use Ronanchilvers\Silex\Security\Encoder\PasswordHashEncoder;
use Ronanchilvers\Silex\Security\Exception\ConfigurationException;
use Ronanchilvers\Silex\Security\Middleware\LogoutMiddleware;
use Ronanchilvers\Silex\Security\Middleware\UsernamePasswordMiddleware;
use Ronanchilvers\Silex\Security\Token\Storage\SessionStorage;
use Ronanchilvers\Silex\Security\Twig\SecurityExtension;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\BootableProviderInterface;
use Silex\Application;
use Silex\Route;

class SecurityProvider implements
    ServiceProviderInterface,
    BootableProviderInterface
{
    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function register(Container $container)
    {
        $container['security.login.path'] = '/login';
        $container['security.check.path'] = '/login-check';
        $container['security.logout.path'] = '/logout';
        $container['security.home.path'] = '/';
        $container['security.auth.manager'] = function ($container) {
            $manager = new AuthenticationManager(
                $container['security.token.storage']
            );
            if (
                isset($container['security.providers']) &&
                is_array($container['security.providers'])
            ) {
                foreach ($container['security.providers'] as $provider) {
                    $manager->registerProvider($provider);
                }
            }

            return $manager;
        };
        $container['security.password.encoder'] = function() {
            return new PasswordHashEncoder();
        };
        $container['security.user.provider'] = null;
        $container['security.provider.form'] = function ($container) {
            if (!$container['security.user.provider'] instanceof UserProviderInterface) {
                throw new ConfigurationException(
                    'User provider not configured : security.user.provider'
                );
            }
            return new UsernamePasswordProvider(
                $container['security.user.provider'],
                $container['security.password.encoder']
            );
        };
        $container['security.middleware.form.check'] = function ($container) {
            return new UsernamePasswordMiddleware();
        };
        $container['security.middleware.logout'] = function ($container) {
            return new LogoutMiddleware();
        };
        $container['security.token.storage'] = function($container) {
            return new SessionStorage($container['session']);
        };
        $container['token'] = $container->factory(function($container) {
            return $container['security.token.storage']->getToken();
        });
        $container['user'] = function ($container) {
            $token = $container['token'];
            if (!$token->isAuthenticated()) {
                return false;
            }

            return $container['security.user.provider']->loadByIdentifier(
                $token->getIdentifier()
            );
        };
    }

    /**
     * Bootstraps the application.
     *
     * This method is called after all services are registered
     * and should be used for "dynamic" configuration (whenever
     * a service must be requested).
     *
     * @param Application $app
     */
    public function boot(Application $app)
    {
        if (!is_null($app['security.check.path'])) {
            $manager = $app['security.auth.manager'];
            if (!$manager->hasProvider($app['security.provider.form'])) {
                $manager->registerProvider($app['security.provider.form']);
            }
            $app->before([$app['security.middleware.form.check'], 'handle']);
        }
        $app->before([$app['security.middleware.logout'], 'handle']);
        $app['twig']->addExtension(
            new SecurityExtension($app['security.token.storage'])
        );
    }
}
