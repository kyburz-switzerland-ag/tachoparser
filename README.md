# Tachoparser

Decode and verify tachograph data (VU data and driver card data).

Inpired by [ReadESM](https://sourceforge.net/projects/readesm/) and [Go Tachograph Card](https://github.com/kuznetsovin/go_tachograph_card) / [Parse tacho's card file](https://medium.com/@kuznetsovin/parse-tachos-card-file-a1daa3f4a5a6), but developed from scratch based on the specs.

## BUILDING and INSTALLATION

### Public keys

For proper data verification, the public keys (root ca and member states) are required.
The Python scripts `pks1/dl_all_pks1.py` and `pks2/dl_all_pks2.py` download and rename all available public keys, first generation (digital tachograph) public keys are expected to be in `pks1`, second generation (smart tachograph) public keys are expected in `pks2`.

```bash
cd pks1
./dl_all_pks1.py
cd ..
cd pks2
./dl_all_pks2.py
cd ..
```

Alternatively, they can be downloaded manually from [ERCA certificates DT](https://dtc.jrc.ec.europa.eu/dtc_public_key_certificates_dt.php.html) and [ERCA certificates ST](https://dtc.jrc.ec.europa.eu/dtc_public_key_certificates_st.php.html), but have to be renamed to their certificate reference (resp. unzipped in case of the root certificate) in this case.

### BUILDING

In the root directory, execute
```bash
./build-binaries-prod.sh
```

Alternatively, execute
```bash
go mod vendor
```
And then change the working directory to `cmd/dddparser` (or any of the other subdirectories of `cmd/`) and execute
```bash
go build .
```

The project aims to have as little external dependencies as possible, currently there are the following external dependencies (most of them are actually not strictly required and could be removed with little effort):

- [brainpool elliptic curve definitions (go-crypto)](https://github.com/keybase/go-crypto)
- [character mappings (x/text)](https://golang.org/x/text)
- [hashicorp consul api](https://github.com/hashicorp/consul)
- [hashicorp sockaddr](https://github.com/hashicorp/go-sockaddr)
- [zenity (ui)](https://github.com/ncruces/zenity)
- [gRPC](https://google.golang.org/grpc)
- [protobuf](https://google.golang.org/protobuf)
- [statsd](https://gopkg.in/alexcesaro/statsd.v2)

The executables that are build are the following:
- `dddparser` is the main executable which parses tachograph / driver card data into a json structure.
- `dddsimple` is a very simplified version which only extracts the identification numbers and driver names
- `dddui` is a basic UI for dddparser (select an input tacho file, select an output json file, select the file type (VU or card))
- `dddserver` is a gRPC server for tachograph file parsing
- `dddclient` is a basic gRPC client which connects to the dddserver

### Docker build

The Dockerfile in the main directory will create a docker image containing only the `dddserver` executable.

### Testing

There are unit tests for decoding different data types.
To run, type
```bash
> go test
```

### INSTALLATION

Put the executable `cmds/dddparser/dddparser` to a location that is in your `PATH`, f.e.
```bash
> sudo cp cmds/dddparser/dddparser /usr/local/bin
```

## USAGE

The executable `dddparser` reads raw data from `STDIN` and outputs JSON data to `STDOUT`, warnings and errors are sent to `STDERR`.

`dddparser` requires one parameter option, which has to be either `-card` or `-vu` depending on the type of data (`-card` is for driver card data, `-vu` is for vehicle unit data).

Example:
```bash
> cat tachodata.ddd | ./dddparser -vu
```

The executable `dddsimple` reads raw data from `STDIN` and outputs JSON data to `STDOUT`, warnings and errors are sent to `STDERR`.

`dddsimple` has one optional argument `-card` which indicates that the input data is driver card data, if not given, it is assumed to be vehicle unit data.

Example:
```bash
> cat driverdata.ddd | ./dddsimple -card
```

The executable `dddserver` starts a gRPC server which listens on port 50055 for incoming requests. The server can be started with the following command:
```bash
> ./dddserver
```
To change the port, use the `-listen` option:
```bash
> ./dddserver -listen :50056
```

## Tipps and Tricks

For output formatting and further processing, [jq](https://stedolan.github.io/jq/) is recommended, f.e.:
```bash
> cat tachodata.ddd | dddparser -vu | jq . | less
```

## TODO

- [x] parse 1st generation driver card data
- [x] parse 2nd generation driver card data
- [x] parse 2nd generation v2 driver card data
- [x] parse 1st generation vu data
- [x] parse 2nd generation vu data
- [x] parse 2nd generation v2 vu data
- [x] signature verification 1st generation
- [x] signature verification 2nd generation
- [ ] complete unit tests for all data types
