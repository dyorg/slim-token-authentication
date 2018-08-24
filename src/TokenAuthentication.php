<?php
declare(strict_types=1);

/*
 * This file is part of Slim Token Authentication Middleware
 *
 * Copyright (c) 2016-2018 Dyorg Washington G. Almeida
 *
 * Licensed under the MIT license
 * http://www.opensource.org/licenses/mit-license.php
 */

namespace Dyorg;

use Dyorg\TokenAuthentication\Exceptions\UnauthorizedException;
use Dyorg\TokenAuthentication\Exceptions\UnauthorizedExceptionInterface;
use Dyorg\TokenAuthentication\TokenSearch;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

class TokenAuthentication
{
    private $options = [
        'secure' => true,
        'relaxed' => ['localhost', '127.0.0.1'],
        'header' => 'Authorization',
        'regex' => '/Bearer\s+(.*)$/i',
        'parameter' => 'authorization',
        'cookie' => 'authorization',
        'argument' => 'authorization',
        'attribute' => 'authorization_token',
        'path' => null,
        'passthrough' => null,
        'authenticator' => null,
        'error' => null
    ];

    public function __construct(array $options = [])
    {
        $this->options['error'] = [$this, 'dafaultError'];

        /** Rewrite options */
        $this->fill($options);

        if (is_null($this->options['authenticator']))
            throw new RuntimeException('Authenticator option has not been setted.');
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next) : ResponseInterface
    {
        try {

            /** If rules say we should not authenticate call next and return. */
            if ($this->shouldAuthenticate($request) === false) {
                return $next($request, $response);
            }

            /** HTTP allowed only if secure is false or server is in relaxed array. */
            $scheme = $request->getUri()->getScheme();
            $host = $request->getUri()->getHost();
            if ($scheme !== 'https' && $this->options['secure'] === true) {
                if (!in_array($host, (array) $this->options['relaxed']))
                    throw new UnauthorizedException('Required HTTPS for token authentication.');
            }

            /** Call custom authenticator function */
            $authenticator_response = $this->options['authenticator']($request, new TokenSearch($this->options));
            if ($authenticator_response === false)
                throw new UnauthorizedException('Invalid authentication token.');

            return $next($request, $response);

        } catch (UnauthorizedExceptionInterface $e) {

            return $this->errorHandler($request, $response, ['message' => $e->getMessage()]);

        }
    }

    private function fill(array $options = []) : void
    {
        foreach ($options as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                call_user_func([$this, $method], $value);
            }
        }
    }

    public function shouldAuthenticate(ServerRequestInterface $request) : bool
    {
        $uri = $request->getUri()->getPath();
        $uri = '/' . trim($uri, '/');

        /** If request path is matches passthrough should not authenticate. */
        foreach ((array) $this->options['passthrough'] as $passthrough) {
            $passthrough = rtrim($passthrough, '/');
            if (preg_match("@^{$passthrough}(/.*)?$@", $uri)) {
                return false;
            }
        }

        /** Otherwise check if path matches and we should authenticate. */
        foreach ((array) $this->options['path'] as $path) {
            $path = rtrim($path, '/');
            if (preg_match("@^{$path}(/.*)?$@", $uri)) {
                return true;
            }
        }

        return false;
    }

    public function errorHandler(ServerRequestInterface $request, ResponseInterface $response, array $arguments = []) : ResponseInterface
    {
        if (isset($this->options['error'])) {

            $error_response = $this->options['error']($request, $response, $arguments);

            if (!$error_response instanceof ResponseInterface)
                throw new RuntimeException('Error function must return a ResponseInterface object type.');

            $response = $error_response;
        }

        return $response;
    }

    private function dafaultError(ServerRequestInterface $request, ResponseInterface $response, array $arguments = []) : ResponseInterface
    {
        $output = [];

        if (isset($arguments['message']))
            $output['message'] = $arguments['message'];

        if (isset($this->options['attribute'])) {
            $output['token'] = $request->getAttribute($this->options['attribute']);
        }

        return $response->withJson($output, 401, JSON_PRETTY_PRINT);
    }

    private function setSecure(bool $secure) : void
    {
        $this->options['secure'] = $secure;
    }

    private function setRelaxed(?array $relaxed) : void
    {
        $this->options['relaxed'] = $relaxed;
    }

    private function setPath($path) : void
    {
        $this->options['path'] = $path;
    }

    private function setPassthrough($passthrough) : void
    {
        $this->options['passthrough'] = $passthrough;
    }

    private function setError(?callable $error) : void
    {
        $this->options['error'] = $error;
    }

    private function setAuthenticator(callable $authenticator) : void
    {
        $this->options['authenticator'] = $authenticator;
    }

    private function setHeader(?string $header) : void
    {
        $this->options['header'] = $header;
    }

    private function setRegex(string $regex) : void
    {
        $this->options['regex'] = $regex;
    }

    private function setParameter(?string $parameter) : void
    {
        $this->options['parameter'] = $parameter;
    }

    private function setArgument(?string $argument) : void
    {
        $this->options['argument'] = $argument;
    }

    private function setCookie(?string $cookie) : void
    {
        $this->options['cookie'] = $cookie;
    }

    private function setAttribute(?string $attribute) : void
    {
        $this->options['attribute'] = $attribute;
    }
}
