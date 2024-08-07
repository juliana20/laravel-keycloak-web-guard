<?php

namespace Julidev\LaravelSsoKeycloak;

use Julidev\LaravelSsoKeycloak\Services\IAMService;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use Julidev\LaravelSsoKeycloak\Auth\Guard\IAMGuard;
use Julidev\LaravelSsoKeycloak\Auth\IAMUserProvider;
use Julidev\LaravelSsoKeycloak\Middleware\Role;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use Illuminate\Auth\Events\Logout;
use Julidev\LaravelSsoKeycloak\Listeners\LogoutListener;
use Julidev\LaravelSsoKeycloak\Middleware\Authentication;
use Julidev\LaravelSsoKeycloak\Middleware\CheckAuthenticated;

class IAMGuardServiceProvider extends ServiceProvider
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
        // Load helpers file
        if (file_exists(__DIR__ . '/helpers.php')) {
            require __DIR__ . '/helpers.php';
        }

        $this->publishes([$config => config_path('sso-web.php')], 'config');
        $this->mergeConfigFrom($config, 'sso-web');

        // Custom guards auth SSO
        config(Arr::dot(config('sso-web.auth', []), 'auth.'));
        
        // User Provider
        Auth::provider('sso-users', function($app, array $config) {
            return new IAMUserProvider($config['model']);
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
            return new IAMGuard($provider, $app->request);
        });
        
        // Facades
        $this->app->bind('iam-badung', function($app) {
            return $app->make(IAMService::class);
        });

        // Routes
        $this->registerRoutes();

        // Middleware Group
        $this->app['router']->middlewareGroup('sso-authentication', [
            StartSession::class,
            Authentication::class, // Custom Middleware
        ]);

        // Add Middleware "sso-role"
        $this->app['router']->aliasMiddleware('sso-role', Role::class);
        $this->app['router']->aliasMiddleware('sso', CheckAuthenticated::class);

        // Bind for client data
        $this->app->when(IAMService::class)->needs(ClientInterface::class)->give(function() {
            return new Client(Config::get('sso-web.guzzle_options', []));
        });

        // Event logout
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
            'auth' => 'sso/auth', // register new route for check auth keycloak
            'backchannel' => 'api/sso/logout' // register new route for backchannel logout
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

        // route tambahan untuk pengecekan apakah sudah login SSO IAM Badung
        if (! empty($routes['auth'])) {
            $router->middleware('sso-authentication')->get($routes['auth'], function(){
                return route('sso.callback');
            })->name('sso.auth');
        }
        // route tambahan untuk proses "Backchannel Logout" pada keycloak server
        if (! empty($routes['backchannel'])) {
            $router->post($routes['backchannel'], 'Julidev\LaravelSsoKeycloak\Controllers\AuthController@backchannel')->name('sso.backchannel');
        }
    }
}
