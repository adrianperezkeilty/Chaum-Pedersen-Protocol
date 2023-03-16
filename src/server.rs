//#![allow(unused)]
use num::Num;
use num_bigint::{BigInt, ToBigInt};
use tonic::{transport::Server, Request, Response, Status};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;

use zkp_auth:: auth_server::{Auth, AuthServer};
use zkp_auth::{
    RegisterRequest, 
    RegisterResponse,
    AuthenticationChallengeRequest,
    AuthenticationChallengeResponse,
    AuthenticationAnswerRequest,
    AuthenticationAnswerResponse
};

use parameters::{public, DATABASE};
use zkp_utils::{
    mod_exp,
    random_big_int,
    default_hash
};

mod zkp_auth;
pub mod parameters; 
pub mod zkp_utils;

#[derive(Default)]
pub struct AuthZKP {}

#[tonic::async_trait]
impl Auth for AuthZKP {

    async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {

        println!("Request={:?}", request);

        let user = &request.get_ref().user;
        let y1 = &request.get_ref().y1;
        let y2 = &request.get_ref().y2;

        let pool = PgPoolOptions::new()
		.max_connections(1)
		.connect(DATABASE)
		.await
        .expect("connection error");

        let user_is_registered = sqlx::query(
            "select exists(select 1 from register_request where auth_id=($1))")
            .bind(&default_hash(user).to_str_radix(16))
            .fetch_one(&pool)
            .await
            .expect("Check User registered failed")
            .get::<bool, usize>(0)
        ;

        if user_is_registered == false {

            // Register new user into database
            sqlx::query(
                "insert into register_request (auth_id, y1, y2) values ($1, $2, $3)")
                .bind(&default_hash(user).to_str_radix(16))
                .bind(y1)
                .bind(y2)
                .execute(&pool)
                .await
                .expect("user insertion error")
            ;
            println!("Registration successful!");
        }
        else {
            println!("Already registered. Please (2) Login instead");
        }

        pool.close().await;

        Ok(Response::new(RegisterResponse{}))
    }

    async fn create_authentication_challenge(&self, request:Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {

        println!("Request={:?}", request);

        let q = public().1;
        let user = &request.get_ref().user;
        let r1 = &request.get_ref().r1;
        let r2 = &request.get_ref().r2;

        let c_hex = random_big_int(2.to_bigint().unwrap(), &q - 1).to_str_radix(16);

        let pool = PgPoolOptions::new()
		.max_connections(1)
		.connect(DATABASE)
		.await
        .expect("Postgres Pool connection failed");

        let user_is_registered = sqlx::query(
            "select exists(select 1 from register_request where auth_id= ($1))")
            .bind(&default_hash(user).to_str_radix(16))
            .fetch_one(&pool)
            .await
            .expect("Check User registered failed")
            .get::<bool, usize>(0)
        ;
            
        // If user is not registered, set auth_id to UserNotRegistered
        // otherwise set auth_id = hash(user)
        let mut auth_id = String::new();

        if user_is_registered == false {
            auth_id.push_str("UserNotRegistered");
        }
        else {
            auth_id.push_str(&default_hash(user).to_str_radix(16));

            // Register or overwrite commitment into database
            sqlx::query(
                "insert into auth_commitment (auth_id, r1, r2) values ($1, $2, $3) 
                on conflict (auth_id) do update set r1 = $2, r2 = $3")
                .bind(&auth_id)
                .bind(r1)
                .bind(r2)
                .execute(&pool)
                .await
                .expect("Commitment insertion error");

            // Register or overwrite challenge into database
            sqlx::query(
                "insert into auth_challenge (auth_id, c) values ($1, $2) 
                on conflict (auth_id) do update set c = $2")
                .bind(&auth_id)
                .bind(&c_hex)
                .execute(&pool)
                .await
                .expect("Challenge insertion error");
        }

        pool.close().await;

        // Send Challenge: random c between 2 and p-2
        Ok(Response::new(AuthenticationChallengeResponse{
            auth_id: auth_id,
            c: c_hex,
        }))
    }

    async fn verify_authentication(&self, request:Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
        
        println!("Request={:?}", request);

        let auth_id = &request.get_ref().auth_id;
        let s = &request.get_ref().s;

        let pool = PgPoolOptions::new()
		.max_connections(1)
		.connect(DATABASE)
		.await
        .expect("Postgres Pool connection failed");

        // Retrieving parameters for verification
        let y1 = sqlx::query(
            "select y1 from register_request where auth_id = ($1)")
            .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving y1")
            .get::<String, usize>(0)
        ;
        let y2 = sqlx::query(
            "select y2 from register_request where auth_id = ($1)")
            .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving y2")
            .get::<String, usize>(0)
        ;
        let r1 = sqlx::query(
            "select r1 from auth_commitment where auth_id = ($1)")
            .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving r1")
            .get::<String, usize>(0)
        ;
        let r2 = sqlx::query(
            "select r2 from auth_commitment where auth_id = ($1)")
            .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving r2")
            .get::<String, usize>(0)
        ;
        // Delete commitment after retrieving it
        sqlx::query(
            "delete from auth_commitment where auth_id = ($1)")
            .bind(auth_id).execute(&pool).await.expect("Error deleting commitment")
        ;
        let c = sqlx::query(
            "select c from auth_challenge where auth_id = ($1)")
            .bind(auth_id).fetch_one(&pool).await.expect("Error retrieving c")
            .get::<String, usize>(0)
        ;
        // Delete challenge for security against the special-soundness property
        sqlx::query(
            "delete from auth_challenge where auth_id = ($1)")
            .bind(auth_id).execute(&pool).await.expect("Error deleting challenge")
        ;

        pool.close().await;

        // Convert back to BigInt
        let y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
        let y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();
        let r1: BigInt = Num::from_str_radix(&r1, 16).unwrap();
        let r2: BigInt = Num::from_str_radix(&r2, 16).unwrap();
        let c: BigInt = Num::from_str_radix(&c, 16).unwrap();
        let s: BigInt = Num::from_str_radix(s, 16).unwrap();

        let (p, _q, g, h) = public();

        let result1 = ((mod_exp(&g.to_bigint().unwrap(), &s, &p ) * mod_exp(&y1, &c, &p) % &p) + &p) % &p;
        let result2 = ((mod_exp(&h.to_bigint().unwrap(), &s, &p) * mod_exp(&y2, &c, &p) % &p) + &p) % &p;
        
        println!("r1 = {}", &r1);
        println!("g^s * y1^c = {}", result1);
        println!("r2 = {}", &r2);
        println!("h^s * y2^c = {}", result2);

        let mut session_id = String::new();

        // Verify equalities
        match &r1 == &result1 && &r2 == &result2 {
            true => {
                println!("Authentication OK!");
                // TODO: Generate session_id
                session_id.push_str("123456abcdef");
            }
            false => {
                println!("Authentication FAILED!");
                session_id.push_str("WrongCredentials");
            }
        }

        Ok(Response::new(AuthenticationAnswerResponse{
            session_id: session_id
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Open connection pool to the database 
	let pool = PgPoolOptions::new()
		.max_connections(1)
		.connect(DATABASE)
		.await
        .expect("Postgres Pool connection failed");

    // Optional: Drop tables at the beginning of each server launch
    // Or keep the database alive in between launches (comment out next 3 commands) 
	sqlx::query(
        "DROP TABLE IF EXISTS register_request"
        )
    .execute(&pool)
    .await?;

    sqlx::query(
        "DROP TABLE IF EXISTS auth_commitment"
        )
    .execute(&pool)
    .await?;

    sqlx::query(
        "DROP TABLE IF EXISTS auth_challenge"
        )
    .execute(&pool)
    .await?;

	sqlx::query("
    CREATE TABLE IF NOT EXISTS register_request (
        auth_id text primary key,
        y1 TEXT NOT NULL,
        y2 TEXT NOT NULL
    )")
	.execute(&pool)
	.await?;

	sqlx::query("
    CREATE TABLE IF NOT EXISTS auth_commitment (
        auth_id text primary key,
        r1 text not null,
        r2 text not null
    )")
	.execute(&pool)
	.await?;

	sqlx::query("
    CREATE TABLE IF NOT EXISTS auth_challenge (
        auth_id text primary key,
        c text not null
    )")
	.execute(&pool)
	.await?;

    pool.close().await;

    let addr = "[::1]:50051".parse().unwrap();

    let auth = AuthZKP::default();
    println!("Server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}