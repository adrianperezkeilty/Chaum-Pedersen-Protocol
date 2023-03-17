# ZKP Chaum Pedersen protocol implementation in Rust

## Parameters:

- $\mathbb{Z}_p^* \rightarrow$ 2048-bit MODP Group described in RFC 3526 (valid for generating a Schnorr group)
- $\equiv\mathbb{Z}_q^*$ $\mathbb{Z}_p^*$  where $q = (p - 1) / 2$
- $(g, h) = (2, 4)$

## Launch Postgres database in docker:

```docker run --name postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres```

## Build the project: 

```cargo build```

## Run in separate terminals:

```cargo run --bin server```

```cargo run --bin client```
