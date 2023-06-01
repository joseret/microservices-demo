yq   '.items[] | .metadata.name + " " + .kind + " " +  .metadata.namespace'   /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/joseret-save/manifests/v2.yaml |  xargs  -n 3     bash  /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/joseret-save/manifests/jrkx.sh  /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/joseret-save/manifests/v2.yaml

kustomize build   /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/kustomize > /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/joseret-save/manifests/v2.yaml
kustomize build   /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/kustomize | yq -s '"compiledjr/" +  .metadata.namespace // "default" + "_" + .metadata.name + "_" + .kind'


docker build --tag  us-docker.pkg.dev/jr-network-infra-1-4978/joseret-joonix-docker/productcatalogservice:4.2.9 /usr/local/google/home/joseret/g/pso/o11y/microservices-demo/src/productcatalogservice
docker push  us-docker.pkg.dev/jr-network-infra-1-4978/joseret-joonix-docker/productcatalogservice:4.2.9
k set image deployment/productcatalogservice server=us-docker.pkg.dev/jr-network-infra-1-4978/joseret-joonix-docker/productcatalogservice:4.2.9

