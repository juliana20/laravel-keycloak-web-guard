<?php

namespace Julidev\LaravelSsoKeycloak;

use Julidev\LaravelSsoKeycloak\Middleware\SsoAuthenticated;
use Julidev\LaravelSsoKeycloak\Services\KeycloakService;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Julidev\LaravelSsoKeycloak\Auth\Guard\KeycloakWebGuard;
use Julidev\LaravelSsoKeycloak\Auth\KeycloakWebUserProvider;
use Julidev\LaravelSsoKeycloak\Middleware\KeycloakCan;
use Illuminate\Support\Arr;
use Julidev\LaravelSsoKeycloak\Middleware\BackchannelLogout;
use Illuminate\Support\Facades\Event;
use Illuminate\Auth\Events\Logout;
use Julidev\LaravelSsoKeycloak\Listeners\LogoutListener;
use Illuminate\Auth\Events\Login;
use Julidev\LaravelSsoKeycloak\Listeners\LoginListener;

class SsoWebGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/keycloak-web.php';

        $this->publishes([$config => config_path('keycloak-web.php')], 'config');
        $this->mergeConfigFrom($config, 'keycloak-web');

        // Custom guards auth SSO
        config(Arr::dot(config('keycloak-web.auth', []), 'auth.'));
        
        // User Provider
        Auth::provider('keycloak-users', function($app, array $config) {
            return new KeycloakWebUserProvider($config['model']);
        });

        // Gate
        Gate::define('keycloak-web', function ($user, $roles, $resource = '') {
            return $user->hasRole($roles, $resource) ?: null;
        });
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        // Keycloak Web Guard
        Auth::extend('keycloak-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new KeycloakWebGuard($provider, $app->request);
        });
        
        // Facades
        $this->app->bind('keycloak-web', function($app) {
            return $app->make(KeycloakService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('sso-authenticated', [
            StartSession::class,
            SsoAuthenticated::class, // Custom Middleware
        ]);

        // Add Middleware "keycloak-web-can"
        $this->app['router']->aliasMiddleware('keycloak-web-can', KeycloakCan::class);
        $this->app['router']->aliasMiddleware('sso', BackchannelLogout::class);

        // Bind for client data
        $this->app->when(KeycloakService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('keycloak-web.guzzle_options', []));
        });

        // Event logout & login
        Event::listen(Logout::class, LogoutListener::class);
        Event::listen(Login::class, LoginListener::class);
    }

    /**
     * Register the authentication routes for keycloak.
     *
     * @return void
     */
    private function registerRoutes()
    {
        \config(['auth.defaults.guard' => 'iam']);
        
        $defaults = [
            'login' => 'login',
            'logout' => 'logout',
            'register' => 'register',
            'callback' => 'callback',
            'sso/auth' => 'sso/auth' // register new route for check auth keycloak
        ];

        $routes = Config::get('keycloak-web.routes', []);
        $routes = array_merge($defaults, $routes);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@login')->name('keycloak.login');
        }
        
        if (! empty($routes['logout'])) {
            $router->middleware('web')->get($routes['logout'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@logout')->name('keycloak.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@register')->name('keycloak.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@callback')->name('keycloak.callback');
        }

        // Custom Routes for SSO check
        if (! empty($routes['sso/auth'])) {
            $router->middleware('sso-authenticated')->get($routes['sso/auth'], function(){
                return redirect( Config::get('keycloak-web.redirect_url'));
            })->name('sso.auth');
        }
    }
}
