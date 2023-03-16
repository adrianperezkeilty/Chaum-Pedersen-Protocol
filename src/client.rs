#![allow(unused)]

use std::io;
use tonic::Response;
use num_bigint::{BigInt, ToBigInt};
use num::Num;

use zkp_auth::auth_client::AuthClient;

use parameters::{public};
use zkp_utils::{
    random_big_int,
    get_user_credentials,
    zkp_register, 
    zkp_authentication_challenge, 
    zkp_verify_authentication};
    
use zkp_auth::{
    RegisterResponse,
    AuthenticationChallengeResponse,
    AuthenticationAnswerResponse
};
mod zkp_auth;
mod parameters;
mod zkp_utils;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Channel for server connection
    let channel = tonic::transport::Channel::from_static("http://[::1]:50051")
    .connect()
    .await?;
    // gRPC client from channel
    let mut client = AuthClient::new(channel);

    let (p, q, g, h) = public();

    println!("______________________Public parameters_____________________");
    println!("p = {}", &p);
    println!("q = {}", &q);
    println!("g = {}", &g);
    println!("h = {}", &h);
    println!("___________________________________________________________");

    let mut option = String::new();
    let mut out = false;

    while !out {

        println!("Please choose an option: (1) Register | (2) Login | (3) Exit");

        option.clear();
        io::stdin()
            .read_line(&mut option)
            .expect("Failed to read option");


        let option: u32 = option.trim().parse().expect("could not convert {option}");

        match option {
            1 => {

                let (username, x) = get_user_credentials();

                // Send (user, y1, y2) to server
                let register_request = zkp_register(&username, &x);

                // Response is an empty struct as per the protobuf
                // If user is already registered, warning will print out in server terminal
                let register_response:Response<RegisterResponse> = client.register(register_request).await?;
                //println!("RESPONSE={:?}", register_response);

            }
            2 => {
                let (username, x) = get_user_credentials();

                // Generate random k in {2, ..., q - 2}
                let k = random_big_int(2.to_bigint().unwrap(), &q - 2);

                // Send (user, r1, r2) to server
                let authentication_challenge_request = zkp_authentication_challenge(&username, &k);
                let authentication_challenge_response:Response<AuthenticationChallengeResponse> = client
                    .create_authentication_challenge(authentication_challenge_request)
                    .await?;
                //println!("RESPONSE={:?}", authentication_challenge_response);

                let auth_id = &authentication_challenge_response.get_ref().auth_id;

                // If user was not registered, alert and go back to loop
                if auth_id == "UserNotRegistered" {
                    println!("_______________________________________________________");
                    println!("You are not registered! Please register before login!");
                    println!("_______________________________________________________");
                    continue;
                }

                // Receive challenge c
                let c: BigInt = Num::from_str_radix(
                    &authentication_challenge_response.get_ref().c, 
                    16)
                    .unwrap();
    
                println!("_____________________Challenge_________________________");
                println!("c = {}", &c);
                println!("_______________________________________________________");

                // Compute s = k - c * x (mod q)
                let s = (((&k - &c * &x) % (&q)) + (&q)) % (&q);

                println!("_____________________Answer____________________________");
                println!("s = {}", &s);
                println!("_______________________________________________________");

                let authentication_answer_request = zkp_verify_authentication(&s, auth_id);
                let verify_authentication_response:Response<AuthenticationAnswerResponse> = client
                    .verify_authentication(authentication_answer_request)
                    .await?;

                //println!("RESPONSE={:?}", verify_authentication_response);
                let session_id = &verify_authentication_response.get_ref().session_id;

                // Credential Handling
                if session_id == "WrongCredentials" {
                    println!("_______________________________________________________");
                    println!("Wrong Credentials! Please try again later");
                    println!("_______________________________________________________");
                    continue;
                }
                else {
                    println!("_______________________________________________________");
                    println!("Login Succeeded!");
                    println!("_______________________________________________________");
                }

            }
            3 => { out = true;}
            _ => {println!("Invalid input!")}
        }
    }

    Ok(())

}