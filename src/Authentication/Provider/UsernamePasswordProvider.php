<?php

namespace Ronanchilvers\Silex\Security\Authentication\Provider;

use Ronanchilvers\Silex\Security\Authentication\Provider\AuthenticationProviderInterface;
use Ronanchilvers\Silex\Security\Encoder\EncoderInterface;
use Ronanchilvers\Silex\Security\Exception\AuthenticationException;
use Ronanchilvers\Silex\Security\Request\RequestInterface;
use Ronanchilvers\Silex\Security\Request\UsernamePasswordRequest;
use Ronanchilvers\Silex\Security\Token\AuthenticatedToken;
use Ronanchilvers\Silex\Security\UserInterface;
use Ronanchilvers\Silex\Security\UserProviderInterface;

/**
 * Authentication provider for username + password tokens
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class UsernamePasswordProvider implements AuthenticationProviderInterface
{
    /**
     * @var Ronanchilvers\Silex\Security\UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var Ronanchilvers\Silex\Security\Encoder\EncoderInterface
     */
    protected $encoder;

    /**
     * Class constructor
     *
     * @param Ronanchilvers\Silex\Security\UserProviderInterface $userProvider
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(
        UserProviderInterface $userProvider,
        EncoderInterface $encoder
    ) {
        $this->userProvider = $userProvider;
        $this->encoder = $encoder;
    }

    /**
     * Authenticate a token
     *
     * @param Ronanchilvers\Silex\Security\RequestInterface
     * @return ???
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function authenticate(RequestInterface $request)
    {
        $user = $this->userProvider->loadByUsername(
            $request->getUsername()
        );
        if (!$user instanceof UserInterface) {
            throw new AuthenticationException('Invalid credentials');
        }
        if (!$this->encoder->verify(
            $user->getPassword(),
            $request->getPassword()
        )) {
            throw new AuthenticationException('Invalid credentials');
        }

        $token = new AuthenticatedToken();
        $token->setIdentifier(
            $request->getUsername()
        );

        return $token;

    }

    /**
     * Does this provider support a given token
     *
     * @param Ronanchilvers\Silex\Security\RequestInterface
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function supports(RequestInterface $request)
    {
        if ($request instanceof UsernamePasswordRequest) {
            return true;
        }

        return false;
    }
}
