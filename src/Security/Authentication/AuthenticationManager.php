<?php

namespace App\Security\Authentication;

use App\Security\Authentication\AuthenticationManagerInterface;
use App\Security\Authentication\Provider\AuthenticationProviderInterface;
use App\Security\Exception\AuthenticationException;
use App\Security\Token\Storage\StorageInterface;
use App\Security\Request\RequestInterface;
use Exception;

/**
 * Standard authentication manager
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class AuthenticationManager implements AuthenticationManagerInterface
{
    /**
     * @var App\Security\Token\Storage\StorageInterface
     */
    protected $storage;

    /**
     * Array of authentication providers
     *
     * @var array
     */
    protected $providers = [];

    /**
     * @var \Exception
     */
    protected $lastException = null;

    /**
     * Class constructor
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function registerProvider(AuthenticationProviderInterface $provider)
    {
        $this->providers[get_class($provider)] = $provider;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function hasProvider($providerClass)
    {
        if (is_object($providerClass)) {
            $providerClass = get_class($providerClass);
        }
        return isset($this->providers[$providerClass]);
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function authenticate(RequestInterface $token)
    {
        foreach ($this->providers as $provider) {
            if (!$provider->supports($token)) {
                continue;
            }
            $this->lastException = null;
            try {
                $key = $provider->authenticate($token);
                $this->storage->setToken($key);

                return $key;
            } catch (Exception $ex) {
                $this->lastException = $ex;
            }
        }

        throw new AuthenticationException('Authentication failed');
    }

    /**
     * Get the last exception that happened during authentication
     *
     * @return \Exception
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getLastException()
    {
        return $this->lastException;
    }
}
