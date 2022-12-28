<?php

namespace KamrulHaque\LaravelPassportAuth;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class  PassportAuthServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/passport.php', 'passport');
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        Passport::tokensExpireIn(now()->addDays(config('passport.token_expiry_days')));
        Passport::refreshTokensExpireIn(now()->addDays(config('passport.refresh_token_expiry_days')));

        if (request()->is('api/*'))
        {
            ResetPassword::createUrlUsing(function ($notifiable, string $token) {
                return config('passport.frontend_url') . 'reset-password?token=' . $token;
            });
        }

        $this->publishes([
            __DIR__ . '/../config/passport.php' => config_path('passport.php'),
            __DIR__ . '/../stubs/migrations/create_oauth_email_verification_codes_table.php' => database_path('migrations/' . date('Y_m_d_His', time()) . '_create_oauth_email_verification_codes_table.php'),
            __DIR__ . '/../stubs/Models/OauthEmailVerificationCode.php' => app_path('Models/OauthEmailVerificationCode.php'),
            __DIR__ . '/../stubs/Controllers/AuthController.php' => app_path('Http/Controllers/Api/Auth/AuthController.php'),
            __DIR__ . '/../stubs/Resources/UserResource.php' => app_path('Http/Resources/UserResource.php'),
            __DIR__ . '/../stubs/Middleware/RestrictRequestIP.php' => app_path('Http/Middleware/RestrictRequestIP.php'),
            __DIR__ . '/../stubs/routes/passport.php' => base_path('routes/passport.php'),
            __DIR__ . '/../stubs/Mail/EmailVerificationMail.php' => app_path('Mail/EmailVerificationMail.php'),
            __DIR__ . '/../stubs/views/email-verification-mail.blade.php' => resource_path('views/mails/email-verification-mail.blade.php'),
        ], 'laravel-passport-auth');
    }
}
