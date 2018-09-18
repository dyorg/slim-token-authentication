<?php
declare(strict_types=1);
/**
 * Created by PhpStorm.
 * User: Dyorg Washington G. Almeida
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg\TokenAuthentication;

use PHPUnit\Framework\TestCase;
use Slim\Http\Environment;
use Slim\Http\Request;
use Slim\Http\Uri;

class TokenSearchTest extends TestCase
{
    private static $token = 'VGhpcyBpcyBzb21lIHRleHQgdG8gY29udmVydCB2aWEgQ3J5cHQu';

    public function test_should_found_token_from_header()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $tokenSearch = new TokenSearch([
            'header' => 'Authorization',
            'regex' => '/^Bearer\s(.*)$/'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    public function test_should_found_token_from_cookie()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withCookieParams([
                'authorization' => self::$token
            ]);

        $tokenSearch = new TokenSearch([
            'cookie' => 'authorization'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    public function test_should_found_token_from_parameter()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api?authorization=' . self::$token));

        $tokenSearch = new TokenSearch([
            'parameter' => 'authorization'
        ]);

        $token = $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $token);
    }

    /**
     * @expectedException Dyorg\TokenAuthentication\Exceptions\TokenNotFoundException
     */
    public function test_exception_when_token_not_found()
    {
        $request = Request::createFromEnvironment(Environment::mock());

        (new TokenSearch([]))->getToken($request);
    }

    public function test_should_return_token_in_attribute()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $tokenSearch = new TokenSearch([
            'header' => 'Authorization',
            'regex' => '/^Bearer\s(.*)$/',
            'attribute' => 'token'
        ]);

        $tokenSearch->getToken($request);

        $this->assertEquals(self::$token, $request->getAttribute('token'));
    }
}
