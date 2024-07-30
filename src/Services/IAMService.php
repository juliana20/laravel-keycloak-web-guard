<?php

namespace Julidev\LaravelSsoKeycloak\Services;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Julidev\LaravelSsoKeycloak\Auth\AccessToken;
use Julidev\LaravelSsoKeycloak\Exceptions\CallbackException;

class IAMService
{
    /**
     * The Session key for token
     */
    const SSO_SESSION = '_sso_token';
    const SSO_SID = '_sso_sid';

    /**
     * The Session key for state
     */
    const SSO_SESSION_STATE = '_sso_state';

    /**
     * Keycloak URL
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Keycloak Realm
     *
     * @var string
     */
    protected $realm;

    /**
     * Keycloak Client ID
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak Client Secret
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Keycloak OpenId Configuration
     *
     * @var array
     */
    protected $openid;

    /**
     * Keycloak OpenId Cache Configuration
     *
     * @var array
     */
    protected $cacheOpenid;

    /**
     * CallbackUrl
     *
     * @var array
     */
    protected $callbackUrl;

    /**
     * RedirectLogout
     *
     * @var array
     */
    protected $redirectLogout;

    /**
     * The state for authorization request
     *
     * @var string
     */
    protected $state;

    /**
     * The HTTP Client
     *
     * @var ClientInterface
     */
    protected $httpClient;

    /**
     * The Constructor
     * You can extend this service setting protected variables before call
     * parent constructor to comunicate with Keycloak smoothly.
     *
     * @param ClientInterface $client
     * @return void
     */
    public function __construct(ClientInterface $client)
    {
        if (is_null($this->baseUrl)) {
            $this->baseUrl = trim(Config::get('sso-web.base_url'), '/');
        }

        if (is_null($this->realm)) {
            $this->realm = Config::get('sso-web.realm');
        }

        if (is_null($this->clientId)) {
            $this->clientId = Config::get('sso-web.client_id');
        }

        if (is_null($this->clientSecret)) {
            $this->clientSecret = Config::get('sso-web.client_secret');
        }

        if (is_null($this->cacheOpenid)) {
            $this->cacheOpenid = Config::get('sso-web.cache_openid', false);
        }

        if (is_null($this->callbackUrl)) {
            $this->callbackUrl = route('sso.callback');
        }

        if (is_null($this->redirectLogout)) {
            $this->redirectLogout = Config::get('sso-web.redirect_logout');
        }

        $this->state = generate_random_state();
        $this->httpClient = $client;
    }

    /**
     * Return the login URL
     *
     * @link https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
     *
     * @return string
     */
    public function getLoginUrl()
    {
        $url = $this->getOpenIdValue('authorization_endpoint');
        $params = [
            'scope' => 'openid',
            'response_type' => 'code',
            'client_id' => $this->getClientId(),
            'redirect_uri' => $this->callbackUrl,
            'state' => $this->getState(),
        ];

        return build_url($url, $params);
    }

    /**
     * Return the logout URL
     *
     * @return string
     */
    public function getLogoutUrl()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');

        if (empty($this->redirectLogout)) {
            $this->redirectLogout = url('/');
        }

        $params = [
            'client_id' => $this->getClientId()
        ];
        $token = $this->retrieveToken();
        if (! empty($token['id_token'])) {
            $params['post_logout_redirect_uri'] = $this->redirectLogout;
            $params['id_token_hint'] = $token['id_token'];
        }

        return build_url($url, $params);
    }

    /**
     * Return the register URL
     *
     * @link https://stackoverflow.com/questions/51514437/keycloak-direct-user-link-registration
     *
     * @return string
     */
    public function getRegisterUrl()
    {
        $url = $this->getLoginUrl();
        return str_replace('/auth?', '/registrations?', $url);
    }
    /**
     * Get access token from Code
     *
     * @param  string $code
     * @return array
     */
    public function getAccessToken($code)
    {
        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'code' => $code,
            'client_id' => $this->getClientId(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return $token;
    }

    /**
     * Refresh access token
     *
     * @param  string $refreshToken
     * @return array
     */
    public function refreshAccessToken($credentials)
    {
        if (empty($credentials['refresh_token'])) {
            return [];
        }

        $url = $this->getOpenIdValue('token_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'grant_type' => 'refresh_token',
            'refresh_token' => $credentials['refresh_token'],
            'redirect_uri' => $this->callbackUrl,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $token = [];

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);

            if ($response->getStatusCode() === 200) {
                $token = $response->getBody()->getContents();
                $token = json_decode($token, true);
            }
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return $token;
    }

    /**
     * Invalidate Refresh
     *
     * @param  string $refreshToken
     * @return array
     */
    public function invalidateRefreshToken($refreshToken)
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $refreshToken,
        ];

        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        try {
            $response = $this->httpClient->request('POST', $url, ['form_params' => $params]);
            return $response->getStatusCode() === 204;
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return false;
    }

    /**
     * Get access token from Code
     * @param  array $credentials
     * @return array
     */
    public function getUserProfile($credentials)
    {
        $credentials = $this->refreshTokenIfNeeded($credentials);

        $user = [];
        try {
            // Validate JWT Token
            $token = new AccessToken($credentials);

            if (empty($token->getAccessToken())) {
                throw new CallbackException('Access Token is invalid.');
            }

            $claims = array(
                'aud' => $this->getClientId(),
                'iss' => $this->getOpenIdValue('issuer'),
            );

            $token->validateIdToken($claims);

            // Get userinfo
            $url = $this->getOpenIdValue('userinfo_endpoint');
            $headers = [
                'Authorization' => 'Bearer ' . $token->getAccessToken(),
                'Accept' => 'application/json',
            ];

            $response = $this->httpClient->request('GET', $url, ['headers' => $headers]);

            if ($response->getStatusCode() !== 200) {
                throw new CallbackException('Was not able to get userinfo (not 200)');
            }

            $user = $response->getBody()->getContents();
            $user = json_decode($user, true);

            // Validate retrieved user is owner of token
            $token->validateSub($user['sub'] ?? '');
        } catch (GuzzleException $e) {
            log_exception($e);
        } catch (Exception $e) {
            Log::error('[SSO Service] ' . print_r($e->getMessage(), true));
        }

        return $user;
    }

    /**
     * Retrieve Token from Session
     *
     * @return array|null
     */
    public function retrieveToken()
    {
        return session()->get(self::SSO_SESSION);
    }

    /**
     * Save Token to Session
     *
     * @return void
     */
    public function saveToken($credentials)
    {
        session()->put(self::SSO_SESSION, $credentials);
        session()->save();
    }

    /**
     * Remove Token from Session
     *
     * @return void
     */
    public function forgetToken()
    {
        // if (session()->has(self::SSO_SID)) {
        //     session()->forget(self::SSO_SID);
        // }
        session()->forget(self::SSO_SESSION);
        session()->save();
    }

    /**
     * Validate State from Session
     *
     * @return void
     */
    public function validateState($state)
    {
        $challenge = session()->get(self::SSO_SESSION_STATE);
        return (! empty($state) && ! empty($challenge) && $challenge === $state);
    }

    /**
     * Save State to Session
     *
     * @return void
     */
    public function saveState()
    {
        session()->put(self::SSO_SESSION_STATE, $this->state);
        session()->save();
    }

    /**
     * Remove State from Session
     *
     * @return void
     */
    public function forgetState()
    {
        session()->forget(self::SSO_SESSION_STATE);
        session()->save();
    }

    /**
     * Return the client id for requests
     *
     * @return string
     */
    protected function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Return the state for requests
     *
     * @return string
     */
    protected function getState()
    {
        return $this->state;
    }

    /**
     * Return a value from the Open ID Configuration
     *
     * @param  string $key
     * @return string
     */
    protected function getOpenIdValue($key)
    {
        if (! $this->openid) {
            $this->openid = $this->getOpenIdConfiguration();
        }

        return Arr::get($this->openid, $key);
    }

    /**
     * Retrieve OpenId Endpoints
     *
     * @return array
     */
    protected function getOpenIdConfiguration()
    {
        $cacheKey = 'sso_web_guard_openid-' . $this->realm . '-' . md5($this->baseUrl);

        // From cache?
        if ($this->cacheOpenid) {
            $configuration = Cache::get($cacheKey, []);

            if (! empty($configuration)) {
                return $configuration;
            }
        }

        // Request if cache empty or not using
        $url = $this->baseUrl . '/realms/' . $this->realm;
        $url = $url . '/.well-known/openid-configuration';

        $configuration = [];

        try {
            $response = $this->httpClient->request('GET', $url);

            if ($response->getStatusCode() === 200) {
                $configuration = $response->getBody()->getContents();
                $configuration = json_decode($configuration, true);
            }
        } catch (GuzzleException $e) {
            log_exception($e);
            throw new CallbackException('It was not possible to load OpenId configuration: ' . $e->getMessage());
        }

        // Save cache
        if ($this->cacheOpenid) {
            Cache::put($cacheKey, $configuration);
        }

        return $configuration;
    }

    /**
     * Check we need to refresh token and refresh if needed
     *
     * @param  array $credentials
     * @return array
     */
    protected function refreshTokenIfNeeded($credentials)
    {
        if (! is_array($credentials) || empty($credentials['access_token']) || empty($credentials['refresh_token'])) {
            return $credentials;
        }

        $token = new AccessToken($credentials);
        if (! $token->hasExpired()) {
            return $credentials;
        }

        $credentials = $this->refreshAccessToken($credentials);

        if (empty($credentials['access_token'])) {
            $this->forgetToken();
            return [];
        }

        $this->saveToken($credentials);
        return $credentials;
    }

    public function logoutToken()
    {
        $url = $this->getOpenIdValue('end_session_endpoint');
        $credentials = $this->retrieveToken();

        if(empty($credentials)){
            return TRUE;
        }

        $introspection = $this->introspectionEndpoint($credentials);
        if(!$introspection['active']){
            return TRUE;
        }
    
        $params = [
            'client_id' => $this->getClientId(),
            'refresh_token' => $credentials['refresh_token'],
        ];
        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }
        
        $response = [];
        try {
            
            $this->forgetToken();
            
            $request = $this->httpClient->request('POST', $url, [
                'form_params' => $params,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            if ($request->getStatusCode() === 200) {
                $response = $request->getBody()->getContents();
                $response = json_decode($response, true);
            }
            
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return $response;
    }

    public function logoutBackchannel($logout_token)
    {
        try {
            // public key dari keycloak server sesuai realm
            $public_key = "-----BEGIN PUBLIC KEY-----\n" . config('sso-web.realm_public_key') . "\n-----END PUBLIC KEY-----";
            // membagi token JWT menjadi tiga bagian
            list($header_encoded, $payload_encoded, $signature_encoded) = explode('.', $logout_token);
            // decode JWT
            $header = json_decode(base64_url_decode($header_encoded), true);
            $payload = json_decode(base64_url_decode($payload_encoded), true);
            $signature = base64_url_decode($signature_encoded);
            // verifikasi algorithm
            if ($header['alg'] !== 'RS256') {
                throw new CallbackException('Unsupported algorithm');
            }
            // verifikasi signature
            $verify_signature = function ($input, $signature, $key) {
                return openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
            };
            // buat string data untuk diverifikasi
            $data_to_verify = "$header_encoded.$payload_encoded";
        
            // verifikasi signature
            $is_valid = $verify_signature($data_to_verify, $signature, openssl_pkey_get_public($public_key));
        
            if ($is_valid) {
                // jika Signature valid, proses payload
                $decoded_array = (array) $payload;
                Log::info('[SSO Service] SSO Logout'. json_encode($decoded_array));
                // pengecekan jika 'sid' ada di payload
                if (isset($decoded_array['sid'])) {
                    // mengambil ID sesi tambahan dari session
                    $sid = $decoded_array['sid'];
                    $session_path = config('sso-web.session_impersonate.path');
                    // menghapus file sesi tambahan jika ada
                    if ($sid) {
                        $session_file = "{$session_path}/{$sid}";
                        if (file_exists($session_file)) {
                            unlink($session_file);
                        }
                    }
                }
            } else {
                throw new CallbackException('Invalid token signature');
            }
        
        } catch (\Exception $e) {
            Log::error('[SSO Service] ' . print_r($e, true));
        }
    }

    public function introspectionEndpoint($credentials)
    {
        if(empty($credentials)){
            return TRUE;
        }

        $url = $this->getOpenIdValue('introspection_endpoint');
        
        $params = [
            'client_id' => $this->getClientId(),
            'token' => $credentials['access_token'],
        ];
        if (! empty($this->clientSecret)) {
            $params['client_secret'] = $this->clientSecret;
        }

        $response = [];
        try {
            $request = $this->httpClient->request('POST', $url, [
                'form_params' => $params,
                'headers' => [
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ],
            ]);

            if ($request->getStatusCode() === 200) {
                $response = $request->getBody()->getContents();
                $response = json_decode($response, true);
            }
            
        } catch (GuzzleException $e) {
            log_exception($e);
        }

        return $response;
    }
}
