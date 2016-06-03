#!/usr/bin/env bash

kubectl delete rc nginx-ingress-rc
kubectl delete svc -l app=certbot
kubectl delete rc -l app=certbot
kubectl delete rc -l type=letsencrypt
kubectl delete svc -l type=letsencrypt

kubectl delete secrets --all
kubectl delete ing --all