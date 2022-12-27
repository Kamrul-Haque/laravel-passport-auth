<?php

use App\Http\Controllers\Api;
use Illuminate\Support\Facades\Route;

Route::post('login', [Api\Auth\AuthController::class, 'login'])
     ->name('login');
Route::post('register', [Api\Auth\AuthController::class, 'register'])
     ->name('register');
Route::post('forgot-password', [Api\Auth\AuthController::class, 'forgotPassword'])
     ->name('forgot-password');
Route::post('reset-password', [Api\Auth\AuthController::class, 'resetPassword'])
     ->name('reset-password');
Route::post('send-verification-code', [Api\Auth\AuthController::class, 'sendVerificationCode'])
     ->name('send-verification-code');
Route::post('verify-email', [Api\Auth\AuthController::class, 'verifyEmail'])
     ->name('verify-email');
