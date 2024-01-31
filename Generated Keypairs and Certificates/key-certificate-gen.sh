#!/bin/bash

openssl genrsa -out c4.key
openssl rsa -in c4.key –pubout > c4_public.key
openssl req -new -key c4.key -out c4.csr
openssl x509 -req -days 365 -in c4.csr -CA server.crt -CAkey server.key -out c4.crt

openssl genrsa -out c5.key
openssl rsa -in c5.key –pubout > c5_public.key
openssl req -new -key c5.key -out c5.csr
openssl x509 -req -days 365 -in c5.csr -CA server.crt -CAkey server.key -out c5.crt

openssl genrsa -out c6.key
openssl rsa -in c6.key –pubout > c6_public.key
openssl req -new -key c6.key -out c6.csr
openssl x509 -req -days 365 -in c6.csr -CA server.crt -CAkey server.key -out c6.crt

openssl genrsa -out c7.key
openssl rsa -in c7.key –pubout > c7_public.key
openssl req -new -key c7.key -out c7.csr
openssl x509 -req -days 365 -in c7.csr -CA server.crt -CAkey server.key -out c7.crt

openssl genrsa -out c8.key
openssl rsa -in c8.key –pubout > c8_public.key
openssl req -new -key c8.key -out c8.csr
openssl x509 -req -days 365 -in c8.csr -CA server.crt -CAkey server.key -out c8.crt

openssl genrsa -out c9.key
openssl rsa -in c9.key –pubout > c9_public.key
openssl req -new -key c9.key -out c9.csr
openssl x509 -req -days 365 -in c9.csr -CA server.crt -CAkey server.key -out c9.crt

openssl genrsa -out c10.key
openssl rsa -in c10.key –pubout > c10_public.key
openssl req -new -key c10.key -out c10.csr
openssl x1509 -req -days 365 -in c10.csr -CA server.crt -CAkey server.key -out c10.crt