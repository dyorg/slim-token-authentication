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
use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;
use Slim\Route;

class TokenAuthentication
{
    private $options = [
        'secure' => true,
        'relaxed' => ['localhost', '127.0.0.1'],
        'header' => 'Authorization',
        'regex' => '/Bearer\s+(.*)$/i',
        'parameter' => 'authorization',
        'cookie' => 'authorization',
        'attribute' => 'authorization',
        'path' => null,
        'except' => null,
        'authenticator' => null,
        'error' => null
    ];

    public function __construct(array $options)
    {
        $this->options['error'] = [$this, 'dafaultError'];

        /** Rewrite options */
        $this->fill($options);

        if (is_null($this->options['authenticator']))
            throw new InvalidArgumentException('Authenticator option has not been setted.');
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
                    throw new UnauthorizedException('Required HTTPS for token authentication.'.$host);
            }

            /** Call custom authenticator function */
            $authenticator_response = $this->options['authenticator']($request, new TokenSearch($this->options));
            if ($authenticator_response === false)
                throw new UnauthorizedException('Invalid authentication token.');

            return $next($request, $response);

        } catch (UnauthorizedExceptionInterface $e) {

            return $this->errorHandler($request, $response, $e);

        }
    }

    private function fill(array $options = []) : void
    {
        foreach ($options as $key => $value) {
            $method_setter = 'set' . ucfirst($key);
            if (method_exists($this, $method_setter)) {
                call_user_func([$this, $method_setter], $value);
            } else if (array_key_exists($key, $this->options)) {
                $this->options[$key] = $value;
            }
        }
    }

    private function shouldAuthenticate(ServerRequestInterface $request) : bool
    {
        $uri = $request->getUri()->getPath();
        $uri = '/' . trim($uri, '/');

        /** If middleware applied directly to route or to group of routes we should authenticate */
        if ($request->getAttribute('route') instanceof Route && $this->options["except"] === null && $this->options["path"] === null) {
            return true;
        }

        /** If request path is matches except should not authenticate. */
        foreach ((array) $this->options['except'] as $except) {
            $except = rtrim($except, '/');
            if (preg_match("@^{$except}(/.*)?$@", $uri)) {
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

    private function errorHandler(ServerRequestInterface $request, ResponseInterface $response, UnauthorizedExceptionInterface $e) : ResponseInterface
    {
        if (isset($this->options['error'])) {

            $error_response = $this->options['error']($request, $response, $e);

            if (!$error_response instanceof ResponseInterface)
                throw new RuntimeException('Error function must return a ResponseInterface object type.');

            $response = $error_response;
        }

        return $response->withStatus(401);
    }

    protected function dafaultError(ServerRequestInterface $request, ResponseInterface $response, UnauthorizedExceptionInterface $e) : ResponseInterface
    {
        $output = [
            'message' => $e->getMessage()
        ];

        if (isset($this->options['attribute'])) {
            $output['token'] = $request->getAttribute($this->options['attribute']);
        }

        return $response->withJson($output, 401, JSON_PRETTY_PRINT);
    }

    protected function setSecure(bool $secure) : void
    {
        $this->options['secure'] = $secure;
    }

    protected function setRelaxed(?array $relaxed) : void
    {
        $this->options['relaxed'] = $relaxed;
    }

    protected function setError(?callable $error) : void
    {
        $this->options['error'] = $error;
    }

    protected function setAuthenticator(callable $authenticator) : void
    {
        $this->options['authenticator'] = $authenticator;
    }

    protected function setHeader(?string $header) : void
    {
        $this->options['header'] = $header;
    }

    protected function setRegex(string $regex) : void
    {
        $this->options['regex'] = $regex;
    }

    protected function setParameter(?string $parameter) : void
    {
        $this->options['parameter'] = $parameter;
    }

    protected function setCookie(?string $cookie) : void
    {
        $this->options['cookie'] = $cookie;
    }

    protected function setAttribute(?string $attribute) : void
    {
        $this->options['attribute'] = $attribute;
    }
}
