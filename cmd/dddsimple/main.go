package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// a very simplified parser based on byte matching that extracts only the identification numbers and driver names from a tachograph / driver card file

const (
	distanceIdentificationNumber1stGen       = 194 + 194      // distance in bytes after the overview tag: MemberStateCertificate (194 bytes) + VuCertificate (194 bytes)
	distanceRegistrationIdentification1stGen = 194 + 194 + 17 // distance in bytes after the overview tag: MemberStateCertificate (194 bytes) + VuCertificate (194 bytes) + IdentificationNumber (17 bytes)
)

const (
	RecordTypeVehicleIdentificationNumber       = 0x0a
	RecordTypeVehicleRegistrationNumber         = 0x0b
	RecordTypeVehicleRegistrationIdentification = 0x24
)

var (
	overviewTag1stGen                        = []byte{0x76, 0x01}
	overviewTag2ndGen                        = []byte{0x76, 0x21}
	overviewTag2ndGenV2                      = []byte{0x76, 0x31}
	identificationNumberRecordArrayTag       = []byte{RecordTypeVehicleIdentificationNumber, 0x00, 0x11, 0x00, 0x01}       // RecordType, Length (uint16), Number of records (uint16)
	registrationNumberRecordArrayTag         = []byte{RecordTypeVehicleRegistrationNumber, 0x00, 0x0e, 0x00, 0x01}         // RecordType, Length (uint16), Number of records (uint16)
	registrationIdentificationRecordArrayTag = []byte{RecordTypeVehicleRegistrationIdentification, 0x00, 0x0f, 0x00, 0x01} // RecordType, Length (uint16), Number of records (uint16)
)

var (
	cardIdentificationTag1stGen = []byte{0x05, 0x20, 0x00}
	cardIdentificationTag2ndGen = []byte{0x05, 0x20, 0x02}
)

var (
	card   = flag.Bool("card", false, "File is a driver card")
	input  = flag.String("input", "", "Input file (optional, stdin is used if not set)")
	output = flag.String("output", "", "Output file (optional, stdout is used if not set)")
)

func VuNameSuggestion(data []byte) string {
	var name string
	vin, regNr, err := VuExtractIdentificationNumberAndRegistrationNumber(data)
	if err != nil {
		return ""
	}
	vin = strings.Replace(vin, " ", "_", -1)
	regNr = strings.Replace(regNr, " ", "_", -1)
	name = fmt.Sprintf("M_%%s_%s_%s.DDD", regNr, vin)
	re := regexp.MustCompile("[[:^print:]]")
	name = re.ReplaceAllLiteralString(name, "_")
	return name
}

func CardNameSuggestion(data []byte) string {
	var name string
	cn, fn, ln, err := CardExtractCardNumberAndDriverName(data)
	if err != nil {
		return ""
	}
	var driverName string
	if fn != "" {
		driverName = fn[0:1] + "_"
	}
	if ln != "" {
		driverName += ln
	}
	driverName = strings.Replace(driverName, " ", "_", -1)
	name = fmt.Sprintf("C_%%s_%s_%s.DDD", driverName, cn)
	re := regexp.MustCompile("[[:^print:]]")
	name = re.ReplaceAllLiteralString(name, "_")
	return name
}

func VuExtractIdentificationNumberAndRegistrationNumber(data []byte) (idNo string, regNo string, err error) {
	identificationNumber := []byte{}
	registrationNumber := []byte{}

	// 1st Generation
	// there is no other tag to look for, just count the distance from the overview tag
	// we only look for the first occurrence of the overview tag
	if idx := bytes.Index(data, overviewTag1stGen); idx >= 0 {
		idIdx := idx + distanceIdentificationNumber1stGen + len(overviewTag1stGen)
		if len(data[idIdx:]) >= 17 {
			identificationNumber = data[idIdx : idIdx+17]
		}
		regIdx := idx + distanceRegistrationIdentification1stGen + len(overviewTag1stGen) + 1 // +1 -> ignore the NationNumeric byte
		if len(data[regIdx:]) >= 14 {
			registrationNumber = data[regIdx : regIdx+14] // includes CodePage (1 byte) + actual registration number (13 bytes)
		}
	}

	// 2nd Generation V1
	if idx := bytes.Index(data, overviewTag2ndGen); idx >= 0 {
		idx += len(overviewTag2ndGen)
		if idIdx := bytes.Index(data[idx:], identificationNumberRecordArrayTag); idIdx >= 0 {
			idIdx += len(identificationNumberRecordArrayTag)
			if len(data[idx+idIdx:]) >= 17 {
				identificationNumber = data[idx+idIdx : idx+idIdx+17]
				if regIdx := bytes.Index(data[idx+idIdx+17:], registrationNumberRecordArrayTag); regIdx >= 0 {
					regIdx += len(registrationNumberRecordArrayTag)
					if len(data[idx+idIdx+17+regIdx:]) >= 14 {
						registrationNumber = data[idx+idIdx+17+regIdx : idx+idIdx+17+regIdx+14]
					}
				}
			}
		}
	}

	// 2nd Generation V2
	if idx := bytes.Index(data, overviewTag2ndGenV2); idx >= 0 {
		idx += len(overviewTag2ndGenV2)
		if idIdx := bytes.Index(data[idx:], identificationNumberRecordArrayTag); idIdx >= 0 {
			idIdx += len(identificationNumberRecordArrayTag)
			if len(data[idx+idIdx:]) >= 17 {
				identificationNumber = data[idx+idIdx : idx+idIdx+17]
				if regIdx := bytes.Index(data[idx+idIdx+17:], registrationIdentificationRecordArrayTag); regIdx >= 0 {
					regIdx += len(registrationIdentificationRecordArrayTag) + 1 // +1 -> ignore the NationNumeric byte
					if len(data[idx+idIdx+17+regIdx:]) >= 14 {
						registrationNumber = data[idx+idIdx+17+regIdx : idx+idIdx+17+regIdx+14]
					}
				}
			}
		}
	}

	if len(identificationNumber) > 0 {
		idNo = trimSpaceAndZero(string(identificationNumber))
	}

	if len(registrationNumber) > 1 {
		regNo, err = decodeWithCodePage(registrationNumber[0], registrationNumber[1:])
		if err != nil {
			return "", "", err
		}
	}

	re := regexp.MustCompile("[[:^print:]]")
	idNo = re.ReplaceAllLiteralString(idNo, "_")
	regNo = re.ReplaceAllLiteralString(regNo, "_")

	if len(idNo) == 0 || len(regNo) == 0 {
		return idNo, regNo, fmt.Errorf("at least one number empty")
	}
	return idNo, regNo, nil
}

func CardExtractCardNumberAndDriverName(data []byte) (cardNo string, firstName string, lastName string, err error) {
	var currentTag [3]byte
	var size uint16
cardLoop:
	for len(data) > 5 {
		// log.Printf("current size: %d actual data size: %d", size, len(data))
		copy(currentTag[:], data[:3])
		data = data[3:]

		buf := bytes.NewBuffer(data[:2])
		err := binary.Read(buf, binary.BigEndian, &size)
		if err != nil {
			// return "", "", "", err
			break cardLoop
		}
		if size == 0 {
			// avoid infinite loop
			break cardLoop
		}
		data = data[2:]
		if len(data) < int(size) {
			// return "", "", "", fmt.Errorf("data too short")
			break cardLoop
		}
		if len(data) > 136 && size > 136 {
			switch {
			case bytes.Equal(currentTag[:], cardIdentificationTag1stGen) || bytes.Equal(currentTag[:], cardIdentificationTag2ndGen):
				// CardIdentificationAndDriverCardHolderIdentification 1st Gen
				// consists of: CardIdentification, DriverCardHolderIdentification
				// CardIdentification:
				// - CardIssuingMemberState (NationNumeric, 1 byte)
				// - CardNumber (16 bytes)
				// - CardIssuingAuthorityName (36 bytes, 1 byte code page + 35 bytes data)
				// - CardIssueDate (TimeReal, 4 bytes)
				// - CardValidityBegin (TimeReal, 4 bytes)
				// - CardExpiryDate (TimeReal, 4 bytes)
				// DriverCardHolderIdentification:
				// - CardHolderName (HolderName)
				//   - HolderSurname (Name, 36 bytes, 1 byte code page + 35 bytes data)
				//   - HolderFirstName (Name, 36 bytes, 1 byte code page + 35 bytes data)
				// - CardHolderBirthDate (Datef)
				//   - Year (BCDString, 2 bytes)
				//   - Month (BCDString, 1 byte)
				//   - Day (BCDString, 1 byte)
				// - CardHolderPreferredLanguage (Language, 2 bytes)
				cardNo = trimSpaceAndZero(string(data[1:17]))
				lastName, _ = decodeWithCodePage(data[65], data[66:101])
				firstName, _ = decodeWithCodePage(data[101], data[102:137])
			}
		}
		data = data[size:]
	}
	if len(cardNo) == 0 || (len(lastName) == 0 && len(firstName) == 0) {
		return "", "", "", fmt.Errorf("at least one entry empty")
	}
	re := regexp.MustCompile("[[:^print:]]")
	cardNo = re.ReplaceAllLiteralString(cardNo, "_")
	firstName = re.ReplaceAllLiteralString(firstName, "_")
	lastName = re.ReplaceAllLiteralString(lastName, "_")
	return cardNo, firstName, lastName, nil
}

// trimSpaceAndZero trims spaces, 0x00 and 0xff values off a string
func trimSpaceAndZero(s string) string {
	w := "\t\n\v\f\r \x85\xA0\x00\xFF"
	return strings.Trim(s, w)
}

func decodeWithCodePage(codePage byte, data []byte) (string, error) {
	ok := false
	for i := 0; i < len(data); i++ {
		if data[i] > 0 && data[i] < 255 {
			ok = true
			break
		}
	}
	if !ok {
		return "", nil
	}
	// 1: 8859-1
	// 2: 8859-2
	// 3: 8859-3
	// 5: 8859-5
	// 7: 8859-7
	// 9: 8859-9
	// 13: 8859-13
	// 15: 8859-15
	// 16: 8859-16
	// 80: KOI8-R
	// 85: KOI8-U
	var cmap *charmap.Charmap
	switch codePage {
	case 1:
		cmap = charmap.ISO8859_1
	case 2:
		cmap = charmap.ISO8859_2
	case 3:
		cmap = charmap.ISO8859_3
	case 5:
		cmap = charmap.ISO8859_5
	case 7:
		cmap = charmap.ISO8859_7
	case 9:
		cmap = charmap.ISO8859_9
	case 13:
		cmap = charmap.ISO8859_13
	case 15:
		cmap = charmap.ISO8859_15
	case 16:
		cmap = charmap.ISO8859_16
	case 80:
		cmap = charmap.KOI8R
	case 85:
		cmap = charmap.KOI8U
	default:
		cmap = charmap.ISO8859_1
	}
	dec := cmap.NewDecoder()
	res, err := dec.String(string(data))
	if err != nil {
		return "", err
	}
	return trimSpaceAndZero(res), nil
}

func main() {
	flag.Parse()
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
		cardNo, firstName, lastName, err := CardExtractCardNumberAndDriverName(data)
		if err != nil {
			log.Fatalf("error: could not parse card: %v", err)
		}
		cardName := CardNameSuggestion(data)
		c := map[string]string{
			"CardNumber": cardNo,
			"FirstName":  firstName,
			"LastName":   lastName,
			"CardName":   cardName,
		}
		dataOut, err = json.Marshal(c)
		if err != nil {
			log.Fatalf("error: could not marshal card: %v", err)
		}
	} else {
		var err error
		idNo, regNo, err := VuExtractIdentificationNumberAndRegistrationNumber(data)
		if err != nil {
			log.Fatalf("error: could not parse vu data: %v", err)
		}
		vuName := VuNameSuggestion(data)
		v := map[string]string{
			"IdentificationNumber": idNo,
			"RegistrationNumber":   regNo,
			"VuName":               vuName,
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
