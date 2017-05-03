<?php

namespace Ronanchilvers\Silex\Security\Exception;

use RuntimeException;

/**
 * Exception thrown when a user provider cannot find a user for a given
 * username
 *
 * @author Ronan Chilvers <ronan@d3r.com>
 */
class UsernameNotFoundException extends RuntimeException
{
}
