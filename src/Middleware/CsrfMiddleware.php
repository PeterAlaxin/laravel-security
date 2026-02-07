<?php

namespace PeterAlaxin\LaravelSecurity\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;

class CsrfMiddleware extends VerifyCsrfToken
{
    protected function addCookieToResponse($request, $response)
    {
        $statusCode = $response->getStatusCode();

        if ($statusCode === 419 || $statusCode === 401) {
            $redirectRoute = config('security.csrf.redirect_route', 'login');
            $errorMessage = config('security.csrf.error_message', 'Session expired. Please log in again.');

            return redirect()->route($redirectRoute)->with('error', $errorMessage);
        }

        return parent::addCookieToResponse($request, $response);
    }
}
