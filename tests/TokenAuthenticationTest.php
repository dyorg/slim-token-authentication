<?php
declare(strict_types=1);
/**
 * Created by PhpStorm.
 * User: Dyorg Washington G. Almeida
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg;

use Dyorg\TokenAuthentication\Exceptions\UnauthorizedException;
use Dyorg\TokenAuthentication\Exceptions\UnauthorizedExceptionInterface;
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

    private static $token_invalid = 's8E6nodLhR56nqIgjMGR88bHeJEXJxsP';

    private static $user = [ 'name' => 'Acme' ];

    private static $wrong_token_message = 'Wrong token Message';

    public function validAuthenticator(ServerRequestInterface &$request, TokenSearch $tokenSearch) : bool
    {
        $token = $tokenSearch->getToken($request);

        if ($token !== self::$token)
            throw new UnauthorizedException(self::$wrong_token_message);

        $request = $request->withAttribute('user_from_inside_authenticator', self::$user);

        return true;
    }

    public function authenticatorWithReturnFalseWhenUnauthorized(ServerRequestInterface &$request, TokenSearch $tokenSearch) : bool
    {
        $token = $tokenSearch->getToken($request);

        if ($token !== self::$token)
            return false;

        return true;
    }

    public function next()
    {
        return function (ServerRequestInterface $request, ResponseInterface $response) {
            return $response;
        };
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
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_401_and_found_token()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$token_invalid, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_401_and_not_found_token()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'));

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(null, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_401_when_authorizator_return_false()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'authenticatorWithReturnFalseWhenUnauthorized'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function test_should_found_token_from_custom_header()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('X-Token', 'Bearer ' . self::$token);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_custom_header_with_custom_regex()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('X-Token', 'Custom ' . self::$token);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'header' => 'X-Token',
            'regex' => '/^Custom\s(.*)$/'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_token_into_custom_attribute()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'attribute' => 'token'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('token'));
    }

    public function test_should_found_token_from_cookie()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withCookieParams([
                'authorization' => self::$token
            ]);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_custom_cookie()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withCookieParams([
                'cookie-token' => self::$token
            ]);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'cookie' => 'cookie-token'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_found_token_from_query_string_parameter()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api?token_parameter=' . self::$token));

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'parameter' => 'token_parameter'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$token, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_attributes_setted_inside_authenticator()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(self::$user['name'], $request->getAttribute('user_from_inside_authenticator')['name']);
    }

    public function test_should_return_401_without_error_method()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'error' => null
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$token_invalid, $request->getAttribute('authorization_token'));
    }

    public function test_should_return_401_with_message()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api'
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$wrong_token_message, json_decode((string) $response->getBody())->message);
    }

    public function test_should_return_401_with_custom_error()
    {
        $request = Request::createFromEnvironment(Environment::mock())
            ->withUri(Uri::createFromString('https://example.com/api'))
            ->withHeader('Authorization', 'Bearer ' . self::$token_invalid);

        $error = function(ServerRequestInterface $request, ResponseInterface $response, UnauthorizedExceptionInterface $e){

            $output = [
                'custom_message' => $e->getMessage()
            ];

            return $response->withJson($output);

        };

        $auth = new TokenAuthentication([
            'authenticator' => [$this, 'validAuthenticator'],
            'path' => '/api',
            'error' => $error
        ]);

        $response = $auth($request, new Response(), $this->next());

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(self::$wrong_token_message, json_decode((string) $response->getBody())->custom_message);

    }
}