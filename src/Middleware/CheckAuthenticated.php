<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Julidev\LaravelSsoKeycloak\Services\IAMService;

class CheckAuthenticated
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
        // Memeriksa apakah additional session tersedia
        $sso_sid = $request->session()->get(IAMService::SSO_SID);
        if (!$sso_sid) {
            return $next($request);
        }

        $session_file = "{$this->sessionPath}/{$sso_sid}";
        // Memeriksa jika session file SSO tidak ada, maka keluar sesi
        if (!file_exists($session_file)) {
            $logout_invalidate();
        }
        // Memastikan file sesi tambahan ada sebelum mengecek isinya
        if (file_exists($session_file)) {
            $session_data = file_get_contents($session_file);
            $unserialized_data = @unserialize($session_data);
            // Memeriksa apakah unserialize berhasil dan login SSO masih aktif/login
            if ($unserialized_data === false || $unserialized_data === null || is_null(auth('iam')->user()) || !auth('iam')->check()) {
                $logout_invalidate();
            }
        }

        return $next($request);

    }
}
