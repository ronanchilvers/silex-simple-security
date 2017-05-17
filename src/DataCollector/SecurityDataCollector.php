<?php

namespace Ronanchilvers\Silex\Security\DataCollector;

use Exception;
use Ronanchilvers\Silex\Security\Access\AccessManagerInterface;
use Ronanchilvers\Silex\Security\Token\Storage\StorageInterface;
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
     * @var Ronanchilvers\Silex\Security\Access\AccessManagerInterface
     */
    private $accessManager;

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
    public function __construct(
        StorageInterface $tokenStorage,
        AccessManagerInterface $accessManager,
        $logoutUrl
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->accessManager = $accessManager;
        $this->logoutUrl = $logoutUrl;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function collect(Request $request, Response $response, Exception $exception = null)
    {
        $token = $this->tokenStorage->getToken();
        $data = [
            'authentication' => [
                'storageClass' => get_class($this->tokenStorage),
                'tokenClass' => get_class($token),
                'token' => $token,
                'scope' => $token->getScope(),
                'identifier' => $token->getIdentifier(),
                'secret' => $token->getSecret(),
                'authenticated' => $token->isAuthenticated(),
                'logoutUrl' => $this->logoutUrl,
            ],
            'access' => [
                'configuredPaths' => $this->accessManager->getConfiguredPaths(),
                'matchedPaths' => $this->accessManager->getMatchedPaths(),
            ]
        ];
        $this->data = $data;
    }

    /**
     * Get the current token storage class
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getStorageClass()
    {
        return $this->data['authentication']['storageClass'];
    }

    /**
     * Get the current token
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getTokenClass()
    {
        return $this->data['authentication']['tokenClass'];
    }

    /**
     * Get the stored token
     *
     * @return ??
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getToken()
    {
        return $this->data['authentication']['token'];
    }

    /**
     * Get the scope
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getScope()
    {
        return $this->data['authentication']['scope'];
    }

    /**
     * Get the token identifier
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getIdentifier()
    {
        return $this->data['authentication']['identifier'] ?: 'anonymous';
    }

    /**
     * Get the token secret
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getSecret()
    {
        return $this->data['authentication']['secret'];
    }

    /**
     * Is the token authenticated?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAuthenticated()
    {
        return $this->data['authentication']['authenticated'];
    }

    /**
     * Get the logout url
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getLogoutUrl()
    {
        return $this->data['authentication']['logoutUrl'];
    }

    /**
     * Get the headers for the configured paths
     *
     * @return array
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getConfiguredAccessPathHeaders()
    {
        return $this->getArrayHeaders(
            $this->getConfiguredAccessPaths()
        );
    }

    /**
     * Get the headers for the matched paths
     *
     * @return array
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getMatchedAccessPathHeaders()
    {
        return $this->getArrayHeaders(
            $this->getMatchedAccessPaths()
        );
    }

    /**
     * Get the configured access paths for this collector
     *
     * @return array
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getConfiguredAccessPaths()
    {
        return $this->data['access']['configuredPaths'];
    }

    /**
     * Get the matched access paths for this collector
     *
     * @return array
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getMatchedAccessPaths()
    {
        return $this->data['access']['matchedPaths'];
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getName()
    {
        return 'security';
    }

    /**
     * Get a set of array headers
     *
     * @return array
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    protected function getArrayHeaders($array)
    {
        if (0 == count($array)) {
            return [];
        }
        reset($array);

        return array_keys(current($array));
    }
}
