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
        if (auth('iam')->check()) {
            $guards = array_unique(array_filter(explode('|', ($guards[0] ?? ''))));
            if ( !auth('iam')->user()->hasRole($guards) ) {
                throw new AuthorizationException('Forbidden', 403);
            }
        }

        return $next($request);
    }
}
