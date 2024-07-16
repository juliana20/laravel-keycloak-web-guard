<?php

namespace Julidev\LaravelSsoKeycloak\Middleware;

use Closure;
use Illuminate\Http\Request;

class Authenticate
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
        if (empty($guards) && auth('iam')->check()) {
            return $next($request);
        }

        return redirect()->route('sso.login');
    }
}
