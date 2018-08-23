<?php

namespace Dyorg\Middleware\TokenAuthentication\Example\App;

use Dyorg\Middleware\TokenAuthentication\Example\App\Exceptions\UnauthorizedException;

class AuthService
{
    /**
     * It's only a validation example!
     * You should search user (on your database or another repository) by authorization token
     */
    public function getUserByToken($token)
    {
        if ($token !== 'usertokensecret') {

            /**
             * The throwable class must implement UnauthorizedExceptionInterface
             */
            throw new UnauthorizedException('Invalid Token');
        }

        $user = [
            'name' => 'Dyorg',
            'id' => 1,
            'permisssion' => 'admin'
        ];

        return $user;
    }

}