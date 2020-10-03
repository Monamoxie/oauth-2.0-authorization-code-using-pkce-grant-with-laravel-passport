<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;

class DashboardController extends Controller
{

    public function index(Request $request)
    {
        // check if there's an access token for this user to fetch their posts from a resource server
        $userToken = auth()->user()->userOAuthToken;
        $userPosts = [];
         
        if($userToken !== null) {
            // make request to fetch posts with the token
            if($request->user()->userOAuthToken->hasTokenExpired()) {
                return redirect('/dashboard/oauth/refresh');
            }
            $resourceResponse = Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'Bearer '. $userToken->access_token
            ])->get(env('RESOURCE_APP_URL') . 'api/user/resource/posts');
             
            // dd($resourceResponse);
            if($resourceResponse->status() === 200) {
                $userPosts = $resourceResponse->json();
            }
            
        }
       
        return view('dashboard', compact('userPosts'));
    }

    public function approveRequest(Request $request)
    {
       
        $codeVerifier = Str::random(128);

        $codeChallenge = strtr(rtrim(
            base64_encode(hash('sha256', $codeVerifier, true)), '='), '+/', '-_');
      
        setcookie('code_verifier', $codeVerifier, time() + 120, '/');
      
        $query = http_build_query([
            'client_id' => env('CLIENT_ID'),
            'redirect_uri' => env('APP_URL') . 'dashboard/oauth/callback',
            'response_type' => 'code',
            'scope' => 'view-posts', 
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ]);
    
        return redirect(env('RESOURCE_APP_URL') . 'oauth/authorize?' . $query);
    }

    public function requestCallback(Request $request)
    {   
        $codeVerifier = '';
        if(isset($_COOKIE['code_verifier'])) {
            $codeVerifier = $_COOKIE['code_verifier'];
        }
        
        $resourceResponse = Http::post(env('RESOURCE_APP_URL') . 'oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => env('CLIENT_ID'), 
            'redirect_uri' => env('APP_URL') . 'dashboard/oauth/callback',
            'code_verifier' => $codeVerifier,
            'code' => $request->code,
        ]);
         
        $resourceResponse = json_decode($resourceResponse->getBody());
             
        if ($request->user()->userOAuthToken) {
            $request->user()->userOAuthToken()->delete();
        }
         
        if(isset($resourceResponse->access_token)) {
            $request->user()->userOAuthToken()->create([
                'access_token' => $resourceResponse->access_token,
                'expires_in' => $resourceResponse->expires_in,
                'refresh_token' => $resourceResponse->refresh_token
            ]);
        }
      

        return redirect('/dashboard');

    }

    public function refreshToken(Request $request)
    { 
        $userToken = auth()->user()->userOAuthToken;
        
        $resourceResponse = Http::post(env('RESOURCE_APP_URL') . 'oauth/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $userToken->refresh_token,
            'client_id' => env('CLIENT_ID'),
            'redirect_uri' => env('APP_URL') . 'dashboard/oauth/callback',
            'scope' => 'view-posts'
        ]); 

        $resourceResponse = json_decode($resourceResponse->getBody());
        
        $request->user()->userOAuthToken()->update([
            'access_token' => $resourceResponse->access_token,
            'expires_in' => $resourceResponse->expires_in,
            'refresh_token' => $resourceResponse->refresh_token
        ]); 

        return redirect('/dashboard');
    }
}
