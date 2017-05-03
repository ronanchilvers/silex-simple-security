<?php

namespace App\Security\Token\Storage;

use App\Security\Token\TokenInterface;

/**
 * Interface for token storage objects
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface StorageInterface
{
    /**
     * Store a given token
     *
     * @param App\Security\Token\TokenInterface
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function setToken(TokenInterface $token);

    /**
     * Return a token from the store
     *
     * This method should always return a token. In the case of no token being
     * stored this method should return an anonymous token.
     *
     * @return App\Security\Token\TokenInterface
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getToken();

    /**
     * Clear the current token from storage
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function eraseToken();
}
