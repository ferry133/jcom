kubectl apply -f ./config.gen/cloudflare-tunnel-default-secret.yaml
kubectl create secret generic omni-gpg-key --namespace omni --from-file=./config.gen/omni.asc

