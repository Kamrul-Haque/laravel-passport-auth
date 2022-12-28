<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Resources\UserResource;
use App\Mail\EmailVerificationMail;
use App\Models\OauthEmailVerificationCode;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password as PasswordRule;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $valid = $request->validate([
            'client_id' => ['required', 'integer', 'gt:0'],
            'client_secret' => ['required', 'string', 'max:100'],
            'email' => ['required', 'email', 'max:255'],
            'password' => ['required',
                'string',
                'max:255',
                PasswordRule::min(8)
                            ->letters()
                            ->mixedCase()
                            ->numbers()
                            ->symbols()
            ]
        ]);

        if (
            !DB::table('oauth_clients')
               ->where('provider', 'users')
               ->where('id', $valid['client_id'])
               ->where('secret', $valid['client_secret'])
               ->exists()
        )
            return response()->json(['error' => 'Invalid Client'], 400);

        $user = User::where('email', $valid['email'])
                    ->firstOrFail();

        if ($user && Hash::check($valid['password'], $user->password))
        {
            $token = $user->createToken('passport')->accessToken;

            if ($token)
                return response()->json([
                    'message' => 'Logged In Successfully',
                    'user' => new UserResource($user),
                    'token' => $token,
                ]);

            return response()->json(['error' => 'Token Creation Failed'], 500);
        }

        return response()->json(['error' => 'Invalid Credentials'], 401);
    }

    public function register(Request $request)
    {
        $valid = $request->validate([
            'client_id' => ['required', 'integer', 'gt:0'],
            'client_secret' => ['required', 'string', 'max:100'],
            'name' => ['required', 'string', 'max:255',],
            'email' => ['required', 'email', 'max:255', Rule::unique('users')->ignore($this->user)],
            'password' => [
                'required',
                'confirmed',
                PasswordRule::min(8)
                            ->letters()
                            ->mixedCase()
                            ->numbers()
                            ->symbols()
            ],
        ]);

        if (
            !DB::table('oauth_clients')
               ->where('provider', 'users')
               ->where('id', $valid['client_id'])
               ->where('secret', $valid['client_secret'])
               ->exists()
        )
            return response()->json(['error' => 'Invalid Client'], 400);

        if (!OauthEmailVerificationCode::where('email', $valid['email'])->where('is_verified', 1)->count())
            return response()->json(['error' => 'Email is not verified']);

        $valid['password'] = bcrypt($request->password);
        $valid['deleted_at'] = now();

        if (User::create(Arr::except($valid, ['client_id', 'client_secret'])))
            return response()->json(['message' => 'Registered Successfully']);

        return response()->json(['error' => 'Registration failed'], 500);
    }

    public function logout()
    {
        try
        {
            auth()->guard('api')->user()->token()->revoke();

            return response()->json(['message' => 'Successfully Logged Out']);
        }
        catch (\Exception $exception)
        {
            return response()->json($exception->getMessage());
        }
    }

    public function forgotPassword(Request $request)
    {
        $valid = $request->validate([
            'client_id' => ['required', 'integer', 'gt:0'],
            'client_secret' => ['required', 'string', 'max:100'],
            'email' => ['required', 'email']
        ]);

        if (
            !DB::table('oauth_clients')
               ->where('provider', 'users')
               ->where('id', $valid['client_id'])
               ->where('secret', $valid['client_secret'])
               ->exists()
        )
            return response()->json(['error' => 'Invalid Client'], 400);

        $status = Password::broker('users')->sendResetLink(Arr::except($valid, ['client_id', 'client_secret']));

        if ($status === Password::RESET_LINK_SENT)
            return response()->json(['message' => 'Password Reset Link Sent']);

        return response()->json(['error' => __($status)], 500);
    }

    public function resetPassword(Request $request)
    {
        $valid = $request->validate([
            'token' => ['required', 'string'],
            'email' => ['required', 'email', 'max:255'],
            'password' => [
                'required',
                'confirmed',
                'max:255',
                PasswordRule::min(8)
                            ->letters()
                            ->mixedCase()
                            ->numbers()
                            ->symbols()
            ],
        ]);

        $status = Password::broker('users')->reset($valid, function ($user, $password) {
            $user->forceFill([
                'password' => Hash::make($password)
            ])->setRememberToken(Str::random(60));

            $user->save();

            event(new PasswordReset($user));
        });

        if ($status === Password::PASSWORD_RESET)
            return response()->json(['message' => 'Password Reset Successfully']);

        return response()->json(['error' => __($status)], 500);
    }

    public function sendVerificationCode(Request $request)
    {
        $valid = $request->validate([
            'client_id' => ['required', 'integer', 'gt:0'],
            'client_secret' => ['required', 'string', 'max:100'],
            'email' => ['required', 'email', 'max:255']
        ]);

        if (
            !DB::table('oauth_clients')
               ->where('provider', 'users')
               ->where('id', $valid['client_id'])
               ->where('secret', $valid['client_secret'])
               ->exists()
        )
            return response()->json(['error' => 'Invalid Client'], 400);

        if (User::where('email', $valid['email'])->first())
            return response()->json(['message' => 'User Already Exists'], 302);

        if (!OauthEmailVerificationCode::where('email', $valid['email'])->where('is_verified', 1)->count())
        {
            if (
                OauthEmailVerificationCode::where('email', $valid['email'])
                                          ->where('created_at', '>', now()->subMinute())
                                          ->count()
            )
                return response()->json(['message' => 'Please Wait Before Retrying'], 400);

            $verificationCode = OauthEmailVerificationCode::create(['email' => $valid['email']]);
        }
        else
            return response()->json(['message' => 'Email Already Verified']);

        if ($verificationCode)
        {
            try
            {
                Mail::to($valid['email'])->send(new EmailVerificationMail($verificationCode->code));
            }
            catch (\Exception $exception)
            {
                return response()->json(['error' => $exception->getMessage()], 400);
            }

            return response()->json([
                'message' => 'Verification Code Sent Successfully',
                'token' => $verificationCode->token
            ]);
        }

        return response()->json(['error' => 'Failed to generate verification code'], 500);
    }

    public function verifyEmail(Request $request)
    {
        $requestCode = $request->validate([
            'code' => ['required', 'digits:6'],
            'token' => ['required', 'string', 'min:36', 'max:36']
        ]);

        $verificationCode = OauthEmailVerificationCode::where('token', $request->token)->first();

        if ($verificationCode)
        {
            if ($verificationCode->expire_at > now())
            {
                if ($requestCode['code'] == $verificationCode->code)
                {
                    if ($verificationCode->update(['is_verified' => 1]))
                        return response()->json(['message' => 'Email verified successfully',]);

                    return response()->json(['error' => 'Failed to verify email'], 500);
                }

                return response()->json(['error' => 'Invalid Code'], 400);
            }

            return response()->json(['error' => 'Code Has Expired'], 400);
        }

        return response()->json(['error' => 'Invalid Token'], 400);
    }

    public function changePassword(Request $request)
    {
        $valid = $request->validate([
            'old_password' => ['required', 'string', 'max:255'],
            'password' => [
                'required',
                'confirmed',
                PasswordRule::min(8)
                            ->letters()
                            ->mixedCase()
                            ->numbers()
                            ->symbols()
            ],
        ]);

        if (Hash::check($valid['old_password'], auth()->guard('api')->user()->password))
        {
            if (auth()->guard('api')->user()->update(['password' => Hash::make($valid['password'])]))
                return response()->json(['message' => 'Password Updated Successfully']);

            return response()->json(['error' => 'Password update failed'], 500);
        }

        return response()->json(['error' => 'Old password is incorrect'], 500);
    }
}
