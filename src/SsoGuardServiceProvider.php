<?php

namespace Julidev\LaravelSsoKeycloak;

use Julidev\LaravelSsoKeycloak\Middleware\SsoAuthenticated;
use Julidev\LaravelSsoKeycloak\Services\SSOService;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Julidev\LaravelSsoKeycloak\Auth\Guard\SSOGuard;
use Julidev\LaravelSsoKeycloak\Auth\SSOUserProvider;
use Julidev\LaravelSsoKeycloak\Middleware\SSORole;
use Illuminate\Support\Arr;
use Julidev\LaravelSsoKeycloak\Middleware\BackchannelLogout;
use Illuminate\Support\Facades\Event;
use Illuminate\Auth\Events\Logout;
use Julidev\LaravelSsoKeycloak\Listeners\LogoutListener;

class SsoGuardServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        // Configuration
        $config = __DIR__ . '/../config/sso-web.php';

        $this->publishes([$config => config_path('sso-web.php')], 'config');
        $this->mergeConfigFrom($config, 'sso-web');

        // Custom guards auth SSO
        config(Arr::dot(config('sso-web.auth', []), 'auth.'));
        
        // User Provider
        Auth::provider('sso-users', function($app, array $config) {
            return new SSOUserProvider($config['model']);
        });

        // Gate
        Gate::define('sso-web', function ($user, $roles, $resource = '') {
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
        Auth::extend('sso-web', function ($app, $name, array $config) {
            $provider = Auth::createUserProvider($config['provider']);
            return new SSOGuard($provider, $app->request);
        });
        
        // Facades
        $this->app->bind('sso-badung', function($app) {
            return $app->make(SSOService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('sso-authenticated', [
            StartSession::class,
            SsoAuthenticated::class, // Custom Middleware
        ]);

        // Add Middleware "sso-web-can"
        $this->app['router']->aliasMiddleware('sso-web-can', SSORole::class);
        $this->app['router']->aliasMiddleware('sso', BackchannelLogout::class);

        // Bind for client data
        $this->app->when(SSOService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('sso-web.guzzle_options', []));
        });

        // Event logout & login
        Event::listen(Logout::class, LogoutListener::class);
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

        $routes = Config::get('sso-web.routes', []);
        $routes = array_merge($defaults, $routes);

        // Register Routes
        $router = $this->app->make('router');

        if (! empty($routes['login'])) {
            $router->middleware('web')->get($routes['login'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@login')->name('sso.login');
        }
        
        if (! empty($routes['logout'])) {
            $router->middleware('web')->get($routes['logout'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@logout')->name('sso.logout');
        }

        if (! empty($routes['register'])) {
            $router->middleware('web')->get($routes['register'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@register')->name('sso.register');
        }

        if (! empty($routes['callback'])) {
            $router->middleware('web')->get($routes['callback'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@callback')->name('sso.callback');
        }

        // Custom Routes for SSO check
        if (! empty($routes['sso/auth'])) {
            $router->middleware('sso-authenticated')->get($routes['sso/auth'], function(){
                return redirect( Config::get('sso-web.redirect_url'));
            })->name('sso.auth');
        }
    }
}
