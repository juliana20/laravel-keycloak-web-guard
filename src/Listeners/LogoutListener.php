<?php

namespace Julidev\LaravelSsoKeycloak\Listeners;

use Illuminate\Auth\Events\Logout;
use Julidev\LaravelSsoKeycloak\Facades\IAMBadung;

class LogoutListener
{
    /**
     * Create the event listener.
     *
     * @return void
     */
    public function __construct()
    {

    }
    /**
     * Handle the event.
     *
     * @param  Logout  $event
     * @return void
     */
    public function handle(Logout $event)
    {
        IAMBadung::logoutToken();
    }
}