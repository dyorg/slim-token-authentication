<?php

namespace Dyorg\Middleware\TokenAuthentication\Example\App\Exceptions;

use Dyorg\Middleware\TokenAuthentication\Exceptions\UnauthorizedExceptionInterface;
use Exception;

class UnauthorizedException extends Exception implements UnauthorizedExceptionInterface
{

}