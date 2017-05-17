<?php

namespace Ronanchilvers\Silex\Security\Token;

use Ronanchilvers\Silex\Security\Token\TokenFactoryInterface;
use Ronanchilvers\Silex\Security\Token\TokenInterface;
use \RuntimeException;


class TokenFactory implements TokenFactoryInterface
{
    /**
     * @string
     */
    protected $salt;

    /**
     * @var string
     */
    protected $sessionId;

    /**
     * Class constructor
     *
     * @param string $secret
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(
        $salt,
        $sessionId
    ) {
        $this->salt = $salt;
        $this->sessionId = $sessionId;
    }

    /**
     * {@inheritdoc}
     *
     * @author  Ronan Chilvers <ronan@d3r.com>
     */
    public function factory($class)
    {
        if (class_exists($class)) {
            return new $class(
                $this->getSecret()
            );
        }

        throw new RuntimeException('Invalid token class ' . $class);
    }

    /**
     * {@inheritdoc}
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function validate(TokenInterface $token)
    {
        $tokenSecret = $token->getSecret();
        if ($this->getSecret() != $tokenSecret) {
            return false;
        }

        return true;
    }

    /**
     * Get app secret
     *
     * @return string
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    protected function getSecret()
    {
        return sha1($this->salt . $this->sessionId);
    }
}
