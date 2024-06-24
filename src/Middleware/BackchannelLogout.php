<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;

class BackchannelLogout
{
    protected $sessionPath;

    public function __construct()
    {
        $this->sessionPath = config('keycloak-web.additional_session.path');
        if (!File::exists($this->sessionPath)) {
            File::makeDirectory($this->sessionPath, 0755, true);
        }
    }


    public function handle(Request $request, \Closure $next)
    {
        \config(['auth.defaults.guard' => config('keycloak-web.auth.guard')]);
        // Memeriksa additional session
        $additionalSessionId = $request->session()->get('sso_session_id');
        if (!$additionalSessionId) {
            return $next($request);
        }
        
        $sessionFile = "{$this->sessionPath}/{$additionalSessionId}";
        // Memastikan file sesi tambahan ada sebelum membacanya
        if (File::exists($sessionFile)) {
            $sessionData = File::get($sessionFile);
            $unserializedData = unserialize($sessionData);

            // Memeriksa apakah unserialize berhasil
            if ($unserializedData === false) {
                Auth::guard()->logout();
                $request->session()->invalidate();  
            }

        } else {
            Auth::guard()->logout();
            $request->session()->invalidate();
        }

        return $next($request);

    }
}
