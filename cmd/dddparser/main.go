package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	_ "github.com/kyburz-switzerland-ag/tachoparser/internal/pkg/certificates"
	"github.com/kyburz-switzerland-ag/tachoparser/pkg/decoder"
)

var (
	card   = flag.Bool("card", false, "File is a driver card")
	vu     = flag.Bool("vu", false, "File is a vu file")
	input  = flag.String("input", "", "Input file (optional, stdin is used if not set)")
	output = flag.String("output", "", "Output file (optional, stdout is used if not set)")
)

func main() {
	log.Printf("loaded certificates: %v %v", len(decoder.PKsFirstGen), len(decoder.PKsSecondGen))

	flag.Parse()
	if (*card && *vu) || (!*card && !*vu) {
		log.Fatal("either card or vu must be set")
	}

	var data []byte
	if *input == "" {
		var err error
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("error: could not read stdin: %v", err)
		}
	} else {
		var err error
		data, err = os.ReadFile(*input)
		if err != nil {
			log.Fatalf("error: could not read file: %v", err)
		}
	}

	var dataOut []byte
	if *card {
		var err error
		var c decoder.Card
		_, err = decoder.UnmarshalTLV(data, &c)
		if err != nil {
			log.Fatalf("error: could not parse card: %v", err)
		}
		dataOut, err = json.Marshal(c)
		if err != nil {
			log.Fatalf("error: could not marshal card: %v", err)
		}
	} else {
		var err error
		var v decoder.Vu
		_, err = decoder.UnmarshalTV(data, &v)
		if err != nil {
			log.Fatalf("error: could not parse vu data: %v", err)
		}
		dataOut, err = json.Marshal(v)
		if err != nil {
			log.Fatalf("error: could not marshal vu data: %v", err)
		}
	}
	if *output == "" || *output == "-" {
		fmt.Print(string(dataOut))
	} else {
		err := os.WriteFile(*output, dataOut, 0644)
		if err != nil {
			log.Fatalf("error: could not write output file: %v", err)
		}
	}
}
