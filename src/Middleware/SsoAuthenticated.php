<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Julidev\LaravelSsoKeycloak\Middleware\Authenticated;

class SsoAuthenticated extends Authenticated
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure                 $next
     *
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        if (empty($guards) && Auth::check()) {
            return $next($request);
        }

        $this->redirectTo($request);
    }
}
