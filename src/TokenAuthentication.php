<?php

/*
 * This file is part of Slim Token Authentication Middleware
 *
 * Copyright (c) 2016-2018 Dyorg Washington G. Almeida
 *
 * Licensed under the MIT license
 * http://www.opensource.org/licenses/mit-license.php
 */

namespace Dyorg\Middleware;

use Dyorg\Middleware\TokenAuthentication\Exceptions\UnauthorizedException;
use Dyorg\Middleware\TokenAuthentication\Exceptions\UnauthorizedExceptionInterface;
use Dyorg\Middleware\TokenAuthentication\TokenSearch;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

class TokenAuthentication
{
    private $options = [
        'secure' => true,
        'relaxed' => ['localhost', '127.0.0.1'],
        'path' => [],
        'passthrough' => [],
        'authenticator' => null,
        'error' => null,
        'header' => 'Authorization',
        'regex' => '/Bearer\s+(.*)$/i',
        'parameter' => 'authorization',
        'cookie' => 'authorization',
        'argument' => 'authorization',
        'attribute' => 'authorization_token'
    ];

    public function __construct(array $options = [])
    {
        $this->options['error'] = function($request, $response, $arguments){
            return $this->dafaultError($request, $response, $arguments);
        };

        /** Rewrite options */
        $this->fill($options);
    }

    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
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
                if (!in_array($host, $this->options['relaxed']))
                    throw new UnauthorizedException('Required HTTPS for token authentication.');
            }

            /** Call custom authenticator function */
            if (empty($this->options['authenticator']))
                throw new RuntimeException('Authenticator option has not been setted.');

            if (!is_callable($this->options['authenticator']))
                throw new RuntimeException('Authenticator option is not callable.');

            $authenticator_response = $this->options['authenticator']($request, new TokenSearch($this->options));
            if ($authenticator_response === false)
                throw new UnauthorizedException('Invalid authentication token.');

            return $next($request, $response);

        } catch (UnauthorizedExceptionInterface $e) {

            return $this->errorHandler($request, $response, ['message' => $e->getMessage()]);

        }
    }

    private function fill($options = [])
    {
        foreach ($options as $key => $value) {
            $method = 'set' . ucfirst($key);
            if (method_exists($this, $method)) {
                call_user_func([$this, $method], $value);
            }
        }
    }

    public function shouldAuthenticate(ServerRequestInterface $request)
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

    public function errorHandler(ServerRequestInterface $request, ResponseInterface $response, $arguments = [])
    {
        if (!empty($this->options['error'])) {

            if (!is_callable($this->options['error']))
                throw new RuntimeException('Error option is not callable.');

            $error_response = $this->options['error']($request, $response, $arguments);

            if (!$error_response instanceof ResponseInterface)
                throw new RuntimeException('Error function must return a ResponseInterface object.');

            $response = $error_response;
        }

        return $response;
    }

    private function dafaultError(ServerRequestInterface $request, ResponseInterface $response, $arguments = [])
    {
        $output = [];

        if (isset($arguments['message']))
            $output['message'] = $arguments['message'];

        if (!empty($this->options['attribute'])) {
            $token = $request->getAttribute($this->options['attribute']);
            $output['token'] = $token;
        }

        return $response->withJson($output, 401, JSON_PRETTY_PRINT);
    }

    public function setSecure($secure)
    {
        $this->options['secure'] = (bool) $secure;
        return $this;
    }

    public function getSecure()
    {
        return $this->options['secure'];
    }

    public function setRelaxed($relaxed)
    {
        $this->options['relaxed'] = (array) $relaxed;
        return $this;
    }

    public function getRelaxed()
    {
        return $this->options['relaxed'];
    }

    public function setPath($path)
    {
        $this->options['path'] = (array) $path;
        return $this;
    }

    public function getPath()
    {
        return $this->options['path'];
    }

    public function setPassthrough($passthrough)
    {
        $this->options['passthrough'] = (array) $passthrough;
        return $this;
    }

    public function getPassthrough()
    {
        return $this->options['passthrough'];
    }

    public function setError(Callable $error)
    {
        $this->options['error'] = $error;
        return $this;
    }

    public function getError()
    {
        return $this->options['error'];
    }

    public function setAuthenticator(Callable $authenticator)
    {
        $this->options['authenticator'] = $authenticator;
        return $this;
    }

    public function getAuthenticator()
    {
        return $this->options['authenticator'];
    }

    public function setHeader($header)
    {
        $this->options['header'] = $header;
        return $this;
    }

    public function getHeader()
    {
        return $this->options['header'];
    }

    public function setRegex($regex)
    {
        $this->options['regex'] = $regex;
        return $this;
    }

    public function getRegex()
    {
        return $this->options['regex'];
    }

    public function setParameter($parameter)
    {
        $this->options['parameter'] = $parameter;
        return $this;
    }

    public function getParameter()
    {
        return $this->options['parameter'];
    }

    public function setArgument($argument)
    {
        $this->options['argument'] = $argument;
        return $this;
    }

    public function getArgument()
    {
        return $this->options['argument'];
    }

    public function setCookie($cookie)
    {
        $this->options['cookie'] = $cookie;
        return $this;
    }

    public function getCookie()
    {
        return $this->options['cookie'];
    }
}
