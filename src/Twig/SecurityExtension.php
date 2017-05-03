<?php

namespace Ronanchilvers\Silex\Security\Twig;

use Ronanchilvers\Silex\Security\Token\Storage\StorageInterface;
use Twig_Extension;
use Twig_Function;

class SecurityExtension extends Twig_Extension
{
    /**
     * @var Ronanchilvers\Silex\Security\Token\Storage\StorageInterface
     */
    protected $storage;

    /**
     * Class constructor
     *
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    public function getFunctions()
    {
        return [
            new Twig_Function(
                'is_authenticated',
                [$this, 'isAuthenticated']
            ),
            new Twig_Function(
                'is_granted',
                [$this, 'isGranted']
            )
        ];
    }

    /**
     * Is the current key authenticated?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isAuthenticated()
    {
        return $this->storage->getToken()->isAuthenticated();
    }

    /**
     * Is a given role granted access?
     *
     * @return boolean
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function isGranted($role)
    {
        return $this->isAuthenticated();
    }
}
