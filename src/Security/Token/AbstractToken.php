<?php

namespace App\Security\Token;

use App\Security\Token\TokenInterface;
use App\Security\Security;
use \Serializable;

abstract class AbstractToken implements
    TokenInterface,
    Serializable
{
    /**
     * @var string
     */
    private $secret;

    /**
     * @var string
     */
    private $identifier;

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getSecret()
    {
        if (is_null($this->secret)) {
            return sha1(uniqid().microtime());
        }

        return $this->secret;
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Set the identifier for this key
     *
     * @param string $identifier
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;
    }

    /**
     * Is this key authenticated?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAuthenticated()
    {
        if ($this->getScope() !== Security::SCOPE_ANONYMOUS) {
            return true;
        }

        return false;
    }

    /**
     * Serialize method
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function serialize()
    {
        return serialize([
            'secret' => $this->getSecret(),
            'identifier' => $this->getIdentifier()
        ]);
    }

    /**
     * Unserialize
     *
     * @param string $string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function unserialize($string)
    {
        if (!$array = unserialize($string)) {
            return;
        }
        if (isset($array['secret'])) {
            $this->secret = $array['secret'];
        }
        if (isset($array['identifier'])) {
            $this->identifier = $array['identifier'];
        }
    }

    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    abstract public function getScope();
}
