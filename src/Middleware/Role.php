<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Closure;
use Illuminate\Auth\Access\AuthorizationException;

class Role
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
        if (empty($guards) && auth('iam')->check()) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        if (auth('iam')->hasRole($guards)) {
            return $next($request);
        }

        throw new AuthorizationException('Forbidden', 403);
    }
}
