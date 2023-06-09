#![allow(unused)]

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use std::io;
use std::io::Write;
use rpassword::read_password;
use num_bigint::{BigInt, ToBigInt, RandBigInt, Sign};
use num_traits::{Zero, One};
use tonic::Request;
use crate::parameters::public;
use crate::zkp_auth::{
    RegisterRequest, 
    AuthenticationChallengeRequest,
    AuthenticationAnswerRequest};


// Fast algorithm for modular exponentiation
pub fn mod_exp(g: &BigInt, x: &BigInt, q: &BigInt) -> BigInt {

    let one: BigInt = One::one();
    let zero: BigInt = Zero::zero();
    let two: BigInt = &one + &one;

    if q == &one { return zero }
    let mut result = 1.to_bigint().unwrap();

    let mut base = g % q;
    let mut exp = x.clone();
    while &exp > &zero {
        if &exp % &two == one {
            result = result * &base % q;
        }        
        exp = exp >> 1;
        base = &base * &base % q
    }

    (result + q) % q
}

// Generate a random BigInt
pub fn random_big_int(from: BigInt, to: BigInt) -> BigInt {
    rand::thread_rng().gen_bigint_range(&from, &to)
}

pub fn get_user_credentials() -> (String, BigInt) {
    
    let mut username = String::new();

    println!("Please input user:");
    io::stdin()
        .read_line(&mut username)
        .expect("Failed to read username");

    println!("Please input password:");
    
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap();

    // Extract BigInt x from typed password
    let x = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());

    println!("Sshh!! Your password equates to the integer x = {}", x);

    (username, x)
}

pub fn default_hash<T>(obj: T) -> BigInt where T: Hash, {

    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish().to_bigint().unwrap()

}

pub fn zkp_register(username: &String, x: &BigInt) -> Request<RegisterRequest>{

    let (p, q, g, h) = public();

    println!("y1 = {}", mod_exp(&g.to_bigint().unwrap(), &x, &p));
    println!("y2 = {}", mod_exp(&h.to_bigint().unwrap(), &x, &p));

    let y1 = mod_exp(&g.to_bigint().unwrap(), &x, &p).to_str_radix(16);
    let y2 = mod_exp(&h.to_bigint().unwrap(), &x, &p).to_str_radix(16);

    // Register
    tonic::Request::new(
        RegisterRequest {
            user:String::from(username),
            y1: y1,
            y2: y2
        },
    )

}

pub fn zkp_authentication_challenge(username: &String, k: &BigInt) -> Request<AuthenticationChallengeRequest> {

    let (p, q, g, h) = public();

    println!("_____________________Commitment_________________________");

    let r1 = mod_exp(&g.to_bigint().unwrap(), &k, &p);
    let r2 =  mod_exp(&h.to_bigint().unwrap(), &k, &p);

    println!("Random k = {}", k);
    println!("r1 = {}", &r1);
    println!("r2 = {}", &r2);
    println!("_______________________________________________________");

    tonic::Request::new(
        AuthenticationChallengeRequest {
            user:String::from(username),
            r1: r1.to_str_radix(16),
            r2: r2.to_str_radix(16),
        },
    )
}

pub fn zkp_verify_authentication(s: &BigInt, auth_id: &str) -> Request<AuthenticationAnswerRequest> {

    tonic::Request::new(
        AuthenticationAnswerRequest {
            auth_id:String::from(auth_id),
            s: s.to_str_radix(16),
        },
    )
}