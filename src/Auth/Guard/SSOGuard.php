<?php

namespace Julidev\LaravelSsoKeycloak\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Julidev\LaravelSsoKeycloak\Auth\SSOAccessToken;
use Julidev\LaravelSsoKeycloak\Exceptions\SSOCallbackException;
use Julidev\LaravelSsoKeycloak\Models\SSOUser;
use Illuminate\Contracts\Auth\UserProvider;
use Julidev\LaravelSsoKeycloak\Facades\SSOBadung;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Services\SSOService;
use Illuminate\Support\Facades\Auth;

class SSOGuard implements Guard
{
    /**
     * @var null|Authenticatable|SSOUser
     */
    protected $user;
    protected $sessionId;
    protected $sessionPath;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->provider = $provider;
        $this->request = $request;
        if (is_null($this->sessionPath)) {
            $this->sessionPath = Config::get('sso-web.additional_session.path');
            if (!File::exists($this->sessionPath)) {
                File::makeDirectory($this->sessionPath, 0755, true);
            }
        }
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }
    
    public function hasUser()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (empty($this->user)) {
            $this->authenticate();
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        SSOBadung::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @throws SSOCallbackException
     * @return boolean
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = SSOBadung::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = SSOBadung::getUserProfile($credentials);
        if (empty($user)) {
            SSOBadung::forgetToken();

            // if (Config::get('app.debug', false)) {
            //     throw new SSOCallbackException('User cannot be authenticated.');
            // }

            return false;
        }

        // Provide User
        $user = $this->provider->retrieveByCredentials($user);
        $this->setUser($user);

        // Login session local apps
        if(config('sso-web.authentication_defaults.enable')){
            return $this->authenticateImpersonate($credentials, $user);
        }

        return true;
    }

    public function authenticateImpersonate($credentials, $user)
    {
        $user_apps = config('sso-web.authentication_defaults.users_model')::where('user_id_sso', $user->id)->first();
        if(empty($user_apps)){
             if (Config::get('app.debug', false)) {
                throw new SSOCallbackException('SSO users have not been mapped.');
            }

            return false;
        }
        Auth::guard(config('sso-web.auth.guard'))->login($user_apps, false);
        // duplicate session untuk sso
        if (!session()->has(SSOService::SSO_SID)) {
            $this->sessionId = $credentials['session_state'];
            session()->put(SSOService::SSO_SID, $this->sessionId);
        } else {
            $this->sessionId = session()->get(SSOService::SSO_SID);
        }
        // Load additional session data from the file
        $session_file = "{$this->sessionPath}/{$this->sessionId}";
        $additional_session = File::exists($session_file) ? unserialize(File::get($session_file)) : [];

        // Make additional session data available in the request
        $this->request->attributes->set('additional_session', $additional_session);
        $this->request->attributes->set('additional_session', session()->all());

        // Save additional session data back to the file
        $additional_session = $this->request->attributes->get('additional_session');
        File::put($session_file, serialize($additional_session));

        return true;
    }
    
    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array
    */
    public function roles($resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('sso-web.client_id');
        }

        if (! $this->check()) {
            return false;
        }

        $token = SSOBadung::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new SSOAccessToken($token);
        $token = $token->parseAccessToken();

        $resourceRoles = $token['resource_access'] ?? [];
        $resourceRoles = $resourceRoles[ $resource ] ?? [];
        $resourceRoles = $resourceRoles['roles'] ?? [];

        return $resourceRoles;
    }

    /**
     * Check user has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return empty(array_diff((array) $roles, $this->roles($resource)));
    }
}
