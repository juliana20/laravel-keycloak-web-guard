<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', ''),

    /**
     * Keycloak Realm
     *
     * Default is master
     */
    'realm' => env('KEYCLOAK_REALM', 'master'),

    /**
     * The Keycloak Server realm public key (string).
     *
     * @see Keycloak >> Realm Settings >> Keys >> RS256 >> Public Key
     */
    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    /**
     * Keycloak Client ID
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_id' => env('KEYCLOAK_CLIENT_ID', null),

    /**
     * Keycloak Client Secret
     *
     * @see Keycloak >> Clients >> Installation
     */
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', null),

    /**
     * We can cache the OpenId Configuration
     * The result from /realms/{realm-name}/.well-known/openid-configuration
     *
     * @link https://www.keycloak.org/docs/3.2/securing_apps/topics/oidc/oidc-generic.html
     */
    'cache_openid' => env('KEYCLOAK_CACHE_OPENID', false),

    /**
     * Page to redirect after callback if there's no "intent"
     *
     * @see Julidev\LaravelSsoKeycloak\Controllers\AuthController::callback()
     */
    'redirect_url' => env('KEYCLOAK_REDIRECT_AFTER_CALLBACK', '/admin'),
    /**
     * The routes for authenticate
     *
     * Accept a string as the first parameter of route() or false to disable the route.
     *
     * The routes will receive the name "keycloak.{route}" and login/callback are required.
     * So, if you make it false, you shoul register a named 'sso.login' route and extend
     * the Julidev\LaravelSsoKeycloak\Controllers\AuthController controller.
     */
    'routes' => [
        'login' => 'sso/login',
        'logout' => 'sso/logout',
        'register' => 'sso/register',
        'callback' => 'sso/callback',
    ],

    /**
    * GuzzleHttp Client options
    *
    * @link http://docs.guzzlephp.org/en/stable/request-options.html
    */
   'guzzle_options' => [
        'verify' => false
   ],

   // Custom Guards for SSO
   'auth' => [
        'guard' => 'admin', // guard auth default local apps

        'guards' => [
            'iam' => [
                'driver'    => 'sso-web',
                'provider'  => 'users-iam',
            ],
        ],
        'providers' => [
            'users-iam' => [
                'driver'    => 'sso-users',
                'model'     => Julidev\LaravelSsoKeycloak\Models\SSOUser::class,
            ],
        ],
    ],

    // Custom auth default for User SSO
    'authentication_defaults' => [

        'enable' => env('KEYCLOAK_AUTH_DEFAULTS', true),
        // Database connection for following tables.
        'connection' => '',

        // User tables and model.
        'users_table' => 'users',
        'users_model' => App\User::class,
    ],

    'additional_session' => [
        'path' => storage_path(env('SSO_SESSION_PATH', 'framework/sessions_sso'))
    ],
];
