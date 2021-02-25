# ktrace

A packet capture utility that captures the network traffic and reconstruct flow state. It uses LibDSSL to support TLS/SSL decryption.



Development


## Building

Using containerized builder image:

```sh
make download_builder_image
make build_in_container
```

## Usage

See `./ktrace -h`.

### Example

Listen for ingress connections to an HTTP microservice listening on localhost:49383,
forwarding the capture to envoy in visibility mode listening on 127.0.10.10:8080:

```sh
sudo ./ktrace -i lo -eip 127.0.10.10 -httpport 49383#0 -tcpport 0#0 -sslport 0#0 -loglevel info -ingress 8080
```

While `ktrace` is running, you can also invoke `ktrace_stats`:

```console
$ ./ktrace_stats 
Stats time         : Wed Nov 13 14:57:20 CET(+0100) 2019
Opened connections : 3
Closed connections : 3
Missed packets     : 0
Packet received    : 0
Packet dropped     : 0
Envoy connection fail : 0
Send timeout       : 0
```


## About Mesh7, Inc.
Mesh7 provides deep and contextual application layer security in distributed and cloud-native application environments, in a completely frictionless manner while being agnostic to the platform, cloud, environment, and workload type. The solution empowers information security leaders, cloud application security practitioners, and application owners with the observability they need to address security , compliance and security controls for microservices, API-based, and other distributed applications.
