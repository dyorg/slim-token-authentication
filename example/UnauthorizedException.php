<?php

namespace Dyorg\Middleware\TokenAuthentication\Example;

use Dyorg\Middleware\TokenAuthentication\UnauthorizedExceptionInterface;

class UnauthorizedException extends \Exception implements UnauthorizedExceptionInterface
{

}