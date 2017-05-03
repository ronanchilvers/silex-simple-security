<?php

namespace App\Security\Request;

use App\Security\Request\RequestInterface;

/**
 * Authentication request for a form base login with username + password
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class UsernamePasswordRequest implements RequestInterface
{
    /**
     * The username for this request
     *
     * @var string
     */
    protected $username;

    /**
     * The password for this request
     *
     * @var string
     */
    protected $password;

    /**
     * Class constructor
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct($username, $password)
    {
        $this->username = $username;
        $this->password = $password;
    }

    /**
     * Get the username for this request
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Get the password for this request
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getPassword()
    {
        return $this->password;
    }
}
