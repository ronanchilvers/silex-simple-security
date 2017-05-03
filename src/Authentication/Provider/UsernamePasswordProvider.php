<?php

namespace App\Security\Authentication\Provider;

use App\Security\Authentication\Provider\AuthenticationProviderInterface;
use App\Security\Encoder\EncoderInterface;
use App\Security\Exception\AuthenticationException;
use App\Security\Request\RequestInterface;
use App\Security\Request\UsernamePasswordRequest;
use App\Security\Token\AuthenticatedToken;
use App\Security\UserInterface;
use App\Security\UserProviderInterface;

/**
 * Authentication provider for username + password tokens
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class UsernamePasswordProvider implements AuthenticationProviderInterface
{
    /**
     * @var App\Security\UserProviderInterface
     */
    protected $userProvider;

    /**
     * @var App\Security\Encoder\EncoderInterface
     */
    protected $encoder;

    /**
     * Class constructor
     *
     * @param App\Security\UserProviderInterface $userProvider
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
     * @param App\Security\RequestInterface
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
     * @param App\Security\RequestInterface
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
