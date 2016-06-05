<?php
namespace app\middlewares\TokenAuthentication;

use Psr\Http\Message\ServerRequestInterface as Request;

class TokenSearch
{
    private $options = [];

    public function __construct($options = [])
    {
        $this->options = $options;
    }

    public function __invoke(Request $request)
    {
        /* Check for token on header */
        if (isset($this->options['header'])) {
            if ($request->hasHeader($this->options['header'])) {
                $header = $request->getHeader($this->options['header'])[0];
                if (preg_match($this->options['regexp'], $header, $matches)) {
                    return $matches[1];
                }
            }
        }

        /* If nothing on header, try query parameters */
        if (isset($this->options['parameter'])) {
            if (!empty($request->getQueryParams()[$this->options['parameter']]))
                return $request->getQueryParams()[$this->options['parameter']];
        }

        /* If nothing on parameters, try cookies */
        if (isset($this->options['cookie'])) {
            $cookie_params = $request->getCookieParams();
            if (!empty($cookie_params[$this->options["cookie"]])) {
                return $cookie_params[$this->options["cookie"]];
            };
        }

        /* If nothing until now, check argument as last try */
        if (isset($this->options['argument'])) {
            $route = $request->getAttribute('route');
            $argument = $route->getArgument($this->options['argument']);
            if (!empty($argument)) {
                return $argument;
            }
        }

        throw new TokenAuthenticationException('Token not found');
    }
}