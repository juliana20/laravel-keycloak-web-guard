<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Closure;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Facades\SSOBadung;

class ManageAdditionalSession
{
    protected $sessionPath;
    protected $sessionId;

    public function __construct()
    {
        $this->sessionPath = config('sso-web.additional_session.path');
        if (!File::exists($this->sessionPath)) {
            File::makeDirectory($this->sessionPath, 0755, true);
        }
    }

    public function handle($request, Closure $next)
    {
        $sso_token = SSOBadung::retrieveToken();
        // Generate or retrieve the additional session ID
        if (!$request->session()->has('sso_session_id')) {
            $this->sessionId = $sso_token['session_state'] ?? session()->getId();
            $request->session()->put('sso_session_id', $this->sessionId);
        } else {
            $this->sessionId = $request->session()->get('sso_session_id');
        }

        // Load additional session data from the file
        $sessionFile = "{$this->sessionPath}/{$this->sessionId}";
        $additionalSession = File::exists($sessionFile) ? unserialize(File::get($sessionFile)) : [];

        // Make additional session data available in the request
        // $additionalSession['data'] = $sso_token ?? [];
        $request->attributes->set('additional_session', $additionalSession);
        $request->attributes->set('additional_session', $sso_token ?? []);

        $response = $next($request);

        // Save additional session data back to the file
        $additionalSession = $request->attributes->get('additional_session');
        File::put($sessionFile, serialize($additionalSession));

        return $response;
    }
}

