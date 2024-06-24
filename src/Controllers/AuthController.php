<?php

namespace Julidev\LaravelSsoKeycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Julidev\LaravelSsoKeycloak\Exceptions\SSOCallbackException;
use Julidev\LaravelSsoKeycloak\Facades\SSOBadung;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = SSOBadung::getLoginUrl();
        SSOBadung::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        $url = SSOBadung::getLogoutUrl();
        SSOBadung::forgetToken();
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = SSOBadung::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws SSOCallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new SSOCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! SSOBadung::validateState($state)) {
            SSOBadung::forgetState();

            throw new SSOCallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = SSOBadung::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('sso-web.redirect_url', '/admin');
                return redirect()->intended($url);
            }
        }

        return redirect(route('sso.login'));
    }
}
