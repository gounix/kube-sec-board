REGISTRY=registry-tst.int.gounix.nl
IMAGE=kube-sec-board
IMAGE_VERSION=1.0.2
PYVERSION=3.14.5

target:
	buildah build --build-arg PYVERSION=${PYVERSION} -t ${IMAGE}:${IMAGE_VERSION} .
	#buildah login docker.io
	buildah push ${IMAGE}:${IMAGE_VERSION} gounix/${IMAGE}:${IMAGE_VERSION}

