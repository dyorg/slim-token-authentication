<?php
/**
 * Created by PhpStorm.
 * User: HomeOffice
 * Date: 27/08/2018
 * Time: 21:54
 */

namespace Dyorg;

use Dyorg\TokenAuthentication\Exceptions\TokenNotFoundException;
use PHPUnit\Framework\TestCase;

class TokenAuthenticationTest extends TestCase
{
    public  function valid_authenticator()
    {
        return true;
    }

    private function authenticator_with_unathorized_exception()
    {
        throw new TokenNotFoundException;
    }

    /** @test */
    public function token_authentication_is_correctly_instantiated()
    {
        $token_authentication = new TokenAuthentication([
            'authenticator' => [$this, 'valid_authenticator']
        ]);

        $this->assertInstanceOf(TokenAuthentication::class, $token_authentication);
    }

    /** @test */
    public function expect_exception_when_authenticator_is_not_especified()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageRegExp('/authenticator/i');

        new TokenAuthentication([]);
    }

    /** @test */
    public function expect_type_error_when_authenticator_is_not_callable()
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessageRegExp('/must be callable/');

        new TokenAuthentication([
            'authenticator' => 'not_callable'
        ]);
    }

    /** @test */
    public function expect_type_error_when_error_is_not_callable()
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessageRegExp('/must be callable/');

        new TokenAuthentication([
            'error' => 'not_callable'
        ]);
    }

    /** @test */
    public function expect_type_error_when_secure_is_not_boolean()
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessageRegExp('/must be.*boolean/');

        new TokenAuthentication([
            'authenticator' => [$this, 'valid_authenticator'],
            'secure' => ['not', 'boolean']
        ]);
    }
}