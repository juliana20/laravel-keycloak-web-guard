<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Support\Facades\Auth;

class RoleOne
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        if (empty($guards) && auth('iam-badung')->check()) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        foreach ($guards as $guard) {
            if (auth('iam-badung')->hasRole($guard)) {
                return $next($request);
            }
        }

        throw new AuthorizationException('Forbidden', 403);
    }
}
