<?php

namespace Ronanchilvers\Silex\Security\Token;

use Ronanchilvers\Silex\Security\Security;

class AnonymousToken extends AbstractToken
{
    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getScope()
    {
        return Security::SCOPE_ANONYMOUS;
    }
}
