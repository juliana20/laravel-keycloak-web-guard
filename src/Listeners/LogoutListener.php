<?php

namespace Julidev\LaravelSsoKeycloak\Listeners;

use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Request;
use Vizir\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Support\Facades\File;

class LogoutListener
{
    /**
     * Create the event listener.
     *
     * @return void
     */
    protected $sessionPath;
    protected $request;

    public function __construct(Request $request)
    {
        $this->request = $request;
        $this->sessionPath = storage_path('framework/sessions_sso');
    }
    /**
     * Handle the event.
     *
     * @param  Logout  $event
     * @return void
     */
    public function handle(Logout $event)
    {
        // Mengambil ID sesi tambahan dari session
        $additionalSessionId = $this->request->session()->get('sso_session_id');
        // Menghapus file sesi tambahan jika ada
        if ($additionalSessionId) {
            $sessionFile = "{$this->sessionPath}/{$additionalSessionId}";
            if (File::exists($sessionFile)) {
                File::delete($sessionFile);
            }
        }

        KeycloakWeb::logoutToken();
    }
}