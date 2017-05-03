<?php

namespace Ronanchilvers\Silex\Security;

/**
 * Interface for user objects
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
interface UserInterface
{
    /**
     * Get the username for this user
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getUsername();

    /**
     * The encoded password for this user
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getPassword();

    /**
     * Get the salt for this user
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getSalt();
}
