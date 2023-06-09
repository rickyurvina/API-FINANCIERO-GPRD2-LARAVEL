<?php

/** @var \Laravel\Lumen\Routing\Router $router */

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It is a breeze. Simply tell Lumen the URIs it should respond to
| and give it the Closure to call when that URI is requested.
|
*/

$router->get('/', function () use ($router) {
    echo "<h3> Welcome </h3>";
});


$router->group([
    'prefix' => 'api'
], function ($router) {
    /*
     *
     * UNAUTHENTICATED ROUTES
     *
     */
    $router->post('/login', 'AuthController@login');
    $router->post('/register', 'AuthController@register');


    /*
     *
     * AUTHENTICATED ROUTES
     *
     */
    $router->group(
        [
            'middleware' => 'auth',
        ], function ($router) {

        $router->get('/version', function () use ($router) {
            return $router->app->version();
        });

        $router->post('/logout', 'AuthController@logout');
        $router->get('/refresh', 'AuthController@refresh');
        $router->post('/refresh', 'AuthController@refresh');


    });
});


