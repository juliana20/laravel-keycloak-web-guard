<?php

namespace Julidev\LaravelSsoKeycloak\Listeners;

use Illuminate\Auth\Events\Login;
use Julidev\LaravelSsoKeycloak\Middleware\ManageAdditionalSession;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Request;

class LoginListener
{
   /**
     * Create the event listener.
     *
     * @return void
     */
    public function __construct()
    {
        //
    }
    public function handle(Login $event)
    {
        $middleware = App::make(ManageAdditionalSession::class);
        
        // Panggil middleware handle method
        $middleware->handle(Request::instance(), function($request) {
            return response();
        });
    }
}