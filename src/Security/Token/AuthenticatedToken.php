<?php

namespace App\Security\Token;

use App\Security\Security;

class AuthenticatedToken extends AbstractToken
{
    /**
     * @author Ronan Chilvers <ronan@d3r.com>
     */
    public function getScope()
    {
        return Security::SCOPE_AUTHENTICATED;
    }
}
