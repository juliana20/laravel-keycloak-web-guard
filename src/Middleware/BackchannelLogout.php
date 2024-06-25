<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Services\SSOService;

class BackchannelLogout
{
    protected $sessionPath;

    public function __construct()
    {
        $this->sessionPath = config('sso-web.additional_session.path');
    }


    public function handle(Request $request, \Closure $next)
    {
        \config(['auth.defaults.guard' => config('sso-web.auth.guard')]);
        // Memeriksa sso session id
        $sso_sid = $request->session()->get(SSOService::SSO_SESSION_FAKE);
        if (!$sso_sid) {
            return $next($request);
        }
        
        $session_file = "{$this->sessionPath}/{$sso_sid}";
        // Memastikan file sesi tambahan ada sebelum membacanya
        if (File::exists($session_file)) {
            $session_data = File::get($session_file);
            $unserialized_data = unserialize($session_data);

            // Memeriksa apakah unserialize berhasil
            if ($unserialized_data === false) {
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
