<?php
namespace App\Http\Controllers;

use App\User;
use DateTime;
use Illuminate\Http\Request;
use JWTAuth;
use JWTAuthException;

class UserController extends Controller
{
    private function getToken($email, $password)
    {
        $token = null;
        //$credentials = $request->only('email', 'password');

        //image is token, status is remember_token
        try {
            if (!$token = JWTAuth::attempt(['email' => $email, 'password' => $password])) {
                return response()->json([
                    'response' => 'error',
                    'message' => 'Password or email is invalid',
                    'token' => $token,
                ]);
            }
        } catch (JWTAuthException $e) {
            return response()->json([
                'response' => 'error',
                'message' => 'Token creation failed',
            ]);
        }
        return $token;
    }
    public function login(Request $request)
    {
        $user = \App\User::where('email', $request->email)->get()->first();
        if ($user && \Hash::check($request->password, $user->password)) // The passwords match...
        {
            $token = self::getToken($request->email, $request->password);
            $user->image = $token;
            $user->save();
            $response = ['success' => true, 'data' => ['id' => $user->id, 'auth_token' => $user->image, 'name' => $user->username, 'email' => $user->email]];
        } else {
            $response = ['success' => false, 'data' => 'Record doesnt exists'];
        }

        return response()->json($response, 201);
    }
    public function register(Request $request)
    {
        $payload = [
            'password' => $request->password,
            'email' => $request->email,
            'name' => $request->username,
            'image' => '',
            'user_group_id' => 1,
            'salt' => '',
            'firstname' => '',
            'lastname' => '',
            'code' => '',
            'ip' => '',
            'status' => 1,
            'date_added' => new DateTime('now'),
        ];
        $credentials = $request->only('email', 'password');

        $user = new \App\User($payload);
        if ($user->save()) {

            $token = self::getToken($request->email, $request->password); // generate user token

            if (!is_string($token)) {
                return response()->json(['success' => false, 'data' => 'Token generation failed', 'token' => $token], 201);
            }

            $user = \App\User::where('email', $request->email)->get()->first();

            $user->image = $token; // update user token

            $user->save();

            $response = ['success' => true, 'data' => ['name' => $user->username, 'id' => $user->user_id, 'email' => $request->email, 'auth_token' => $token]];
        } else {
            $response = ['success' => false, 'data' => 'Couldnt register user'];
        }

        return response()->json($response, 201);
    }
}
