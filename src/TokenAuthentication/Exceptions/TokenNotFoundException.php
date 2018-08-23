<?php

/*
 * This file is part of Slim Token Authentication Middleware
 *
 * Copyright (c) 2016-2018 Dyorg Washington G. Almeida
 *
 * Licensed under the MIT license
 * http://www.opensource.org/licenses/mit-license.php
 */

namespace Dyorg\Middleware\TokenAuthentication\Exceptions;

use Exception;

class TokenNotFoundException extends Exception implements UnauthorizedExceptionInterface
{

}