<?php

namespace Middleware;

use Closure;
use Illuminate\Http\Request;

class RestrictRequestIP
{
    public function handle(Request $request, Closure $next)
    {
        if (config('passport.frontend_ip'))
            if ($request->ip() != config('passport.frontend_ip'))
                return response()->json(['error' => 'IP not recognized'], 406);

        return $next($request);
    }
}
