<?php

require_once '../vendor/autoload.php';

use Slim\App;
use Dyorg\Middleware\TokenAuthentication;
use Dyorg\Middleware\TokenAuthentication\Example\Auth;

$config = [
    'settings' => [
        'displayErrorDetails' => true
    ]
];

$app = new App($config);

$authenticator = function($request, TokenAuthentication $tokenAuth){

    /**
     * Try find authorization token via header, parameters, cookie or attribute
     * If token not found, return response with status 401 (unauthorized)
     */
    $token = $tokenAuth->findToken($request);

    /**
     * Call authentication logic class
     */
    $auth = new Auth();

    /**
     * Verify if token is valid on database
     * If token isn't valid, must throw an UnauthorizedExceptionInterface
     */
    $auth->getUserByToken($token);

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
    $output = ['msg' => 'It is a public area'];
    return $response->withJson($output, 200, JSON_PRETTY_PRINT);
});

/**
 * Restrict route example
 * Our token is "usertokensecret"
 */
$app->get('/restrict', function($request, $response){
    $output = ['msg' => 'It\'s a restrict area. Token authentication works!'];
    return $response->withJson($output, 200, JSON_PRETTY_PRINT);
});

$app->run();