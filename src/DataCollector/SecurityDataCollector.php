<?php

namespace Ronanchilvers\Silex\Security\DataCollector;

use Ronanchilvers\Silex\Security\Token\Storage\StorageInterface;
use Exception;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\DataCollector\DataCollector;

class SecurityDataCollector extends DataCollector
{
    /**
     * @var Ronanchilvers\Silex\Security\Token\Storage\StorageInterface
     */
    private $tokenStorage;

    /**
     * @var string
     */
    private $logoutUrl;

    /**
     * Class constructor
     *
     * @param Ronanchilvers\Silex\Security\Token\Storage\StorageInterface $tokenStorage
     * @param string $logoutUrl
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(StorageInterface $tokenStorage, $logoutUrl)
    {
        $this->tokenStorage = $tokenStorage;
        $this->logoutUrl = $logoutUrl;
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
            'authenticated' => $token->isAuthenticated(),
            'logoutUrl' => $this->logoutUrl,
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
     * Get the logout url
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getLogoutUrl()
    {
        return $this->data['logoutUrl'];
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getName()
    {
        return 'security';
    }
}
