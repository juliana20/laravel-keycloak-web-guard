<?php

namespace Julidev\LaravelSsoKeycloak\Auth\Guard;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Julidev\LaravelSsoKeycloak\Auth\AccessToken;
use Julidev\LaravelSsoKeycloak\Exceptions\CallbackException;
use Julidev\LaravelSsoKeycloak\Models\IAMUser;
use Illuminate\Contracts\Auth\UserProvider;
use Julidev\LaravelSsoKeycloak\Facades\IAMBadung;
use Illuminate\Support\Facades\File;
use Julidev\LaravelSsoKeycloak\Services\IAMService;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\Access\AuthorizationException;

class IAMGuard implements Guard
{
    /**
     * @var null|Authenticatable|IAMUser
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
            $this->sessionPath = Config::get('sso-web.session_impersonate.path');
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
        IAMBadung::saveToken($credentials);

        return $this->authenticate();
    }

    /**
     * Try to authenticate the user
     *
     * @throws CallbackException
     * @return boolean
     */
    public function authenticate()
    {
        // Get Credentials
        $credentials = IAMBadung::retrieveToken();
        if (empty($credentials)) {
            return false;
        }

        $user = IAMBadung::getUserProfile($credentials);
        if (empty($user)) {
            IAMBadung::forgetToken();

            // if (Config::get('app.debug', false)) {
            //     throw new CallbackException('User cannot be authenticated.');
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
                throw new AuthorizationException('Pengguna belum terdaftar', 403);
            }

            return false;
        }
        Auth::guard(config('sso-web.auth.guard'))->login($user_apps, false);
        // duplicate session untuk sso
        if (!session()->has(IAMService::SSO_SID)) {
            $this->sessionId = $credentials['session_state'];
            session()->put(IAMService::SSO_SID, $this->sessionId);
        } else {
            $this->sessionId = session()->get(IAMService::SSO_SID);
        }
        // Load additional session data from the file
        $session_file = "{$this->sessionPath}/{$this->sessionId}";
        $session_impersonate = File::exists($session_file) ? unserialize(File::get($session_file)) : [];

        // Make additional session data available in the request
        $this->request->attributes->set('session_impersonate', $session_impersonate);
        $this->request->attributes->set('session_impersonate', session()->all());

        // Save additional session data back to the file
        $session_impersonate = $this->request->attributes->get('session_impersonate');
        File::put($session_file, serialize($session_impersonate));

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

        $token = IAMBadung::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new AccessToken($token);
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
