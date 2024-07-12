<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Services\IAMService;

class BackchannelLogout
{
    protected $sessionPath;

    public function __construct()
    {
        $this->sessionPath = config('sso-web.session_impersonate.path');
    }

    public function handle(Request $request, \Closure $next)
    {
        $logout_invalidate = function() use ($request) {
            auth(config('sso-web.auth.guard'))->logout();
            $request->session()->invalidate();
        };
        // Memeriksa additional session
        $sso_sid = $request->session()->get(IAMService::SSO_SID);
        if (!$sso_sid) {
            return $next($request);
        }

        $session_file = "{$this->sessionPath}/{$sso_sid}";
        // Memastikan file sesi tambahan ada sebelum membacanya
        if (File::exists($session_file)) {
            $session_data = File::get($session_file);
            $unserialized_data = @unserialize($session_data);
            // Memeriksa apakah unserialize berhasil dan sso masih aktif/login
            if ($unserialized_data === false || $unserialized_data === null || is_null(auth('iam-badung')->user()) || !auth('iam-badung')->check()) {
                $logout_invalidate();
            }

        } else {
            $logout_invalidate();
        }

        return $next($request);

    }
}
