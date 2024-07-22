<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Services\IAMService;

class IAMAuthenticated
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
            $logout_invalidate();
            return $next($request);
        }

        $session_file = "{$this->sessionPath}/{$sso_sid}";
        // Memeriksa jika session file SSO tidak ada, maka keluar sesi
        if (!File::exists($session_file)) {
            $logout_invalidate();
        }
        // Memastikan file sesi tambahan ada sebelum mengecek isinya
        if (File::exists($session_file)) {
            $session_data = File::get($session_file);
            $unserialized_data = @unserialize($session_data);
            // Memeriksa apakah unserialize berhasil dan login SSO masih aktif/login
            if ($unserialized_data === false || $unserialized_data === null || is_null(auth('iam')->user()) || !auth('iam')->check()) {
                $logout_invalidate();
            }

        }

        return $next($request);

    }
}
