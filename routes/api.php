<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::group(['middleware' => ['cors', 'json.response']], function () {
    Route::post('/login', [App\Http\Controllers\Api\AuthController::class, 'login'])->middleware("throttle:10,2");

    Route::post('/register', [App\Http\Controllers\Api\AuthController::class, 'register']);
});

Route::group(['middleware' => ['json.response', 'cors', 'auth:api']], function () {
    Route::get('/logout', [App\Http\Controllers\Api\AuthController::class, 'logout']);

    Route::get('/user', function (Request $request) {
	    return $request->user();
	});

});