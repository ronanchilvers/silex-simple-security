<?php

namespace Ronanchilvers\Silex\Security;

/**
 * Interface for user provider objects
 *
 * User Providers implement the bridge between the authentication system and
 * a user data source of some sort.
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface UserProviderInterface
{
    /**
     * Load a user by username
     *
     * @param string $username
     * @return Ronanchilvers\Silex\Security\UserInterface
     * @throws UsernameNotFoundException
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function loadByUsername($username);

    /**
     * Load by identifier
     *
     * Load a user by a unique identifier
     *
     * @param mixed identifier
     * @return Ronanchilvers\Silex\Security\UserInterface
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function loadByIdentifier($identifier);
}
