<?php

namespace Julidev\LaravelSsoKeycloak\Helpers;

class JWT {
    static function base64UrlDecode($input) {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }
}