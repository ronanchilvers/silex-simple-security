<?php

namespace App\Security\DataCollector;

use App\Security\Token\Storage\StorageInterface;
use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

class SecurityDataCollector extends DataCollector
{
    /**
     * @var App\Security\Token\Storage\StorageInterface
     */
    private $tokenStorage;

    /**
     * Class constructor
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(StorageInterface $tokenStorage)
    {
        $this->tokenStorage = $tokenStorage;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function collect(Request $request, Response $response, Exception $exception = null)
    {
        $token = $this->tokenStorage->getToken();
        $this->data = [
            'storageClass' => get_class($this->tokenStorage),
            'tokenClass' => get_class($token),
            'token' => $token,
            'scope' => $token->getScope(),
            'identifier' => $token->getIdentifier(),
            'secret' => $token->getSecret(),
            'authenticated' => $token->isAuthenticated()
        ];
    }

    /**
     * Get the current token storage class
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getStorageClass()
    {
        return $this->data['storageClass'];
    }

    /**
     * Get the current token
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getTokenClass()
    {
        return $this->data['tokenClass'];
    }

    /**
     * Get the stored token
     *
     * @return ??
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getToken()
    {
        return $this->data['token'];
    }

    /**
     * Get the scope
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getScope()
    {
        return $this->data['scope'];
    }

    /**
     * Get the token identifier
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getIdentifier()
    {
        return $this->data['identifier'] ?: 'n/a';
    }

    /**
     * Is the token authenticated?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAuthenticated()
    {
        return $this->data['authenticated'];
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getName()
    {
        return 'security';
    }
}
