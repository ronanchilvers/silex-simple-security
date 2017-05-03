<?php

namespace App\Security\Token\Storage;

use App\Security\Token\AnonymousToken;
use App\Security\Token\TokenInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;

class SessionStorage implements StorageInterface
{
    const STORAGE_KEY = 'security.token.storage.session';

    /**
     * @var Symfony\Component\HttpFoundation\Session\SessionInterface
     */
    protected $session;

    /**
     * Class constructor
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(SessionInterface $session)
    {
        $this->session = $session;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function setToken(TokenInterface $token)
    {
        $this->session->set(
            static::STORAGE_KEY,
            $token
        );
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getToken()
    {
        return $this->session->get(
            static::STORAGE_KEY,
            new AnonymousToken()
        );
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function eraseToken()
    {
        return $this->session->remove(
            static::STORAGE_KEY
        );
    }
}
