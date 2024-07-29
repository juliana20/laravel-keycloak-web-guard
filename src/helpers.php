<?php

use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Facades\Log;

if (!function_exists('base64_url_decode')) {
    function base64_url_decode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}

/**
 * Return a random state parameter for authorization
 *
 * @return string
 */
if (!function_exists('generate_random_state')) {
    function generate_random_state()
    {
        return bin2hex(random_bytes(16));
    }
}

/**
 * Build a URL with params
 *
 * @param  string $url
 * @param  array $params
 * @return string
 */
if (!function_exists('build_url')) {
     function build_url($url, $params)
     {
         $parsedUrl = parse_url($url);
         if (empty($parsedUrl['host'])) {
             return trim($url, '?') . '?' . http_build_query($params);
         }
 
         if (! empty($parsedUrl['port'])) {
             $parsedUrl['host'] .= ':' . $parsedUrl['port'];
         }
 
         $parsedUrl['scheme'] = (empty($parsedUrl['scheme'])) ? 'https' : $parsedUrl['scheme'];
         $parsedUrl['path'] = (empty($parsedUrl['path'])) ? '' : $parsedUrl['path'];
 
         $url = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . $parsedUrl['path'];
         $query = [];
 
         if (! empty($parsedUrl['query'])) {
             $parsedUrl['query'] = explode('&', $parsedUrl['query']);
 
             foreach ($parsedUrl['query'] as $value) {
                 $value = explode('=', $value);
 
                 if (count($value) < 2) {
                     continue;
                 }
 
                 $key = array_shift($value);
                 $value = implode('=', $value);
 
                 $query[$key] = urldecode($value);
             }
         }
 
         $query = array_merge($query, $params);
 
         return $url . '?' . http_build_query($query);
     }
}

/**
 * Log a GuzzleException
 *
 * @param  GuzzleException $e
 * @return void
 */
if (!function_exists('log_exception')) {
    function log_exception(GuzzleException $e)
    {
        // Guzzle 7
        if (! method_exists($e, 'getResponse') || empty($e->getResponse())) {
            Log::error('[SSO Service] ' . $e->getMessage());
            return;
        }

        $error = [
            'request' => method_exists($e, 'getRequest') ? $e->getRequest() : '',
            'response' => $e->getResponse()->getBody()->getContents(),
        ];

        Log::error('[SSO Service] ' . print_r($error, true));
    }
}