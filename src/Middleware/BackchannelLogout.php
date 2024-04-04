<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Julidev\LaravelSsoKeycloak\Facades\KeycloakWeb;

class BackchannelLogout
{
    public function handle(Request $request, \Closure $next)
    {   
        \config(['auth.defaults.guard' => config('keycloak-web.auth.guard')]);

        $credentials = KeycloakWeb::retrieveToken();
        if(!empty($credentials)){
            $introspection = KeycloakWeb::introspectionEndpoint($credentials);
            if(!$introspection['active']){
                Auth::guard()->logout();
                $request->session()->invalidate();
            }

            config(['session.lifetime' => $credentials['expires_in']]);
        }

        return $next($request);

    }
}
