<?php

namespace Julidev\LaravelSsoKeycloak\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Julidev\LaravelSsoKeycloak\Exceptions\CallbackException;
use Julidev\LaravelSsoKeycloak\Facades\IAMBadung;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = IAMBadung::getLoginUrl();
        IAMBadung::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        $url = IAMBadung::getLogoutUrl();
        IAMBadung::forgetToken();
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = IAMBadung::getRegisterUrl();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws CallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new CallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! IAMBadung::validateState($state)) {
            IAMBadung::forgetState();

            throw new CallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = IAMBadung::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('sso-web.redirect_url');
                return redirect()->intended($url);
            }
        }

        return redirect(route('sso.login'));
    }

    public function backchannel(Request $request){
        $logout_token = $request->input('logout_token'); // get logout token from keycloak server
        IAMBadung::logoutBackchannel($logout_token);
    }
}
