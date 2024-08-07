<?php

return [
    /**
     * Keycloak Url
     *
     * Generally https://your-server.com/auth
     */
    'base_url' => env('KEYCLOAK_BASE_URL', 'http://localhost:8080'),

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

   // Add Custom Guards for IAM Badung (SSO)
   'auth' => [
        'guard' => 'admin', // guard default aplikasi laravel

        'guards' => [
            'iam' => [
                'driver'    => 'sso-web',
                'provider'  => 'users-iam',
            ],
        ],
        'providers' => [
            'users-iam' => [
                'driver'    => 'sso-users',
                'model'     => Julidev\LaravelSsoKeycloak\Models\IAMUser::class, #model SSO keycloak
            ],
        ],
    ],

    // Set jika menggunakan session login aplikasi laravel ( 2 sesi)
    'authentication_defaults' => [
        'enable' => env('KEYCLOAK_AUTH_DEFAULTS', true),
        // User tabel dan model aplikasi laravel.
        'users_table' => 'users',
        'users_model' => App\User::class,
        'users_field_sso_id' => 'user_id_sso'
    ],

    // Set path session tiruan SSO
    'session_impersonate' => [
        'path' => storage_path(env('SSO_SESSION_PATH', 'framework/sessions_sso'))
    ],
];
