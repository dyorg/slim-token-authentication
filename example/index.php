<?php

require_once '../vendor/autoload.php';

use Dyorg\Middleware\TokenAuthentication;
use Dyorg\Middleware\TokenAuthentication\Example\App\AuthService;
use Dyorg\Middleware\TokenAuthentication\TokenSearch;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Slim\App;

$config = [
    'settings' => [
        'displayErrorDetails' => true
    ]
];

$app = new App($config);

$authenticator = function(RequestInterface &$request, TokenSearch $tokenSearch){

    /**
     * Try find authorization token via header, parameters, cookie or attribute
     * If token not found, return response with status 401 (unauthorized)
     */
    $token = $tokenSearch->getToken($request);

    /**
     * Call authentication logic class
     */
    $auth = new AuthService();

    /**
     * Verify if token is valid on database
     * If token isn't valid, must throw an UnauthorizedExceptionInterface
     */
    $user = $auth->getUserByToken($token);


    $request = $request->withAttribute('authenticated_user', $user);

};

/**
 * Add token authentication middleware
 */
$app->add(new TokenAuthentication([
    'path' =>   '/restrict',
    'authenticator' => $authenticator,
    'relaxed' => true
]));

/**
 * Public route example
 */
$app->get('/', function($request, $response){
    $output = ['message' => 'It\'s a public area'];
    return $response->withJson($output, 200, JSON_PRETTY_PRINT);
});

/**
 * Restrict route example
 * Our token is "usertokensecret"
 */
$app->get('/restrict', function($request, $response){
    $output = ['message' => 'It\'s a restrict area. Token authentication works!'];
    return $response->withJson($output, 200, JSON_PRETTY_PRINT);
});

$app->run();