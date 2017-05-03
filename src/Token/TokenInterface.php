<?php

namespace App\Security\Token;

/**
 * Requests are swapped for tokens when a request is authenticated.
 *
 * When an authentication request is processed by the auth provider manager, if
 * the authentication succeeds the manager returns a token object that is
 * serialisable. This is the object that is stored in the session (for example)
 * and used in subsequent requests.
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface TokenInterface
{
    /**
     * Get the secret for this token
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getSecret();

    /**
     * Get the user identifier for this token
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getIdentifier();

    /**
     * Get the scope of this token
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getScope();

    /**
     * Is this token authenticated?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAuthenticated();
}
