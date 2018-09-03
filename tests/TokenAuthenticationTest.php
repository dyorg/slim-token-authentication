<?php
declare(strict_types=1);
/**
 * Created by PhpStorm.
 * User: Dyorg Washington G. Almeida
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg;

use Dyorg\TokenAuthentication\Exceptions\TokenNotFoundException;
use Dyorg\TokenAuthentication\TokenSearch;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Http\Environment;
use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;

class TokenAuthenticationTest extends TestCase
{
    private static $token = 'VGhpcyBpcyBzb21lIHRleHQgdG8gY29udmVydCB2aWEgQ3J5cHQu';

    private static $user = [ 'name' => 'Acme' ];

    public function validAuthenticator(ServerRequestInterface &$request, TokenSearch $tokenSearch)
    {
        $token = $tokenSearch->getToken($request);

        $request = $request->withAttribute('user_from_inside_authenticator', self::$user);

        return true;
    }

    private function authenticator_with_unathorized_exception()
    {
        throw new TokenNotFoundException;
    }

    public function test_token_authentication_is_instantiable()
    {
        $token_authentication = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator']
        ]);

        $this->assertInstanceOf(TokenAuthentication::class, $token_authentication);
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessageRegExp /authenticator.+not.+setted/i
     */
    public function test_exception_when_authenticator_is_not_especified()
    {
        new TokenAuthentication([]);
    }

    public function invalidCallables()
    {
        return [
            [''],
            [0],
            [1],
            [true],
            [false],
            ['callable'],
            ['string'],
            [[]],
            [['acme', 'corp']]
        ];
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \TypeError
     * @expectedExceptionMessageRegExp /must be.+callable/
     */
    public function test_exception_when_authenticator_is_not_callable($invalid_callable)
    {
        new TokenAuthentication([
            'authenticator' => $invalid_callable
        ]);
    }

    /**
     * @dataProvider invalidCallables
     * @expectedException \TypeError
     * @expectedExceptionMessageRegExp /must be.+callable/
     */
    public function test_exception_when_error_is_not_callable($invalid_callable)
    {
        new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'error' => $invalid_callable
        ]);
    }

    public function test_should_found_token_from_default_header()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_custom_header()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('X-Token', 'Bearer ' . self::$token );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_custom_header_with_custom_regex()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('X-Token', 'Custom ' . self::$token );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token',
            'regex' => '/^Custom\s(.*)$/'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_token_into_custom_attribute()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'attribute' => 'token'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('token'));
    }

    public function test_should_found_token_from_cookie()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withCookieParams([
                'cookie-token' => self::$token
            ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'cookie' => 'cookie-token'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_query_string_parameter()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api?token_parameter=' . self::$token));

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'parameter' => 'token_parameter'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_attributes_setted_inside_authenticator()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$user['name'], $request->getAttribute('user_from_inside_authenticator')['name']);

    }

    public function test_should_return_default_error()
    {
        new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
        ]);
    }

    public function test_should_return_custom_error()
    {
        new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
        ]);
    }

    public function test_should_return_none_error()
    {
        new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
        ]);
    }
}