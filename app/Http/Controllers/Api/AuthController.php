<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Auth\Events\Registered;
use App\Models\User;
use Carbon\Carbon;

class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Api Auth Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the api login and registration as well as their
    | validation and creation
    |
    |
    */

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest');
        $this->uploadPath = 'profile';
        $this->file_rule = 'mimes:jpg,jpeg,png,pdf,xls,xlsx,docx,ppt,pptx,odt';
    }

    /**
     * Handle a login request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function login (Request $request) 
    {
        $status = 200;
        $response = [];

        $validator = $this->loginValidator($request->all());

        if ($validator->fails())
        {
            $status = 422;
            $response['errors'] = $validator->errors()->all();
        }else{
            $status = 422;
            $response['message'] = __('Invalid password.Please try again.');

            $credentials = $request->only('email', 'password');

            if (Auth::attempt($credentials)) {
                $status = 200;
                $user = Auth::user();
                $token = $user->createToken('Authorization Token')->accessToken;
                $response['token']   = $token;
                
                
                
                
                $response['message'] = __('You are successfully logged in.');
            }
        }
//Bearer
        return response($response, $status);
    }
    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }
    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function loginValidator(array $data)
    {
        return Validator::make($data, [
            'email' => ['required', 'string', 'email', 'max:255', 'exists:users,email'],
            'password' => ['required', 'string', 'min:8'],
        ]);
    }

    /**
     * Handle a registration request for the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function register (Request $request) 
    {
        $status = 200;
        $response = [];
        $validator = $this->registerValidator($request->all());
        
        if ($validator->fails())
        {
            $status = 422;
            $response['errors'] = $validator->errors()->all();
            return response(['errors'=>$validator->errors()->all()], 422);
        }else{
            $status = 200;
            $user = $this->create($request->all());
            event(new Registered($user));
            $response['message'] = __('You are registered successfully.');
        }
        

        return response($response, $status);
    }

    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\Models\User
     */
    protected function create(array $data)
    {
        return User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
        ]);
    }

    /**
     * Get a validator for an incoming client(Role) registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function registerValidator(array $data)
    {
        return Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8', 'confirmed'],
        ]);
    }
}