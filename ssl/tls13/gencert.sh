#!/bin/bash

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout hello.pem -out hello.pem