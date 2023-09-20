package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DomainResult represents the result for a single domain, including port status and CDN information.
type DomainResult struct {
	Domain  string
	Port80  bool
	Port443 bool
	IsCDN   bool
	CDNname string
}

func main() {
	// Print usage example and information about the tool.
	fmt.Printf(color.Colorize(color.Green, `Example Of Use : Subcheck.go -i 'C:\Users\**\Desktop\go2\checksubdomains\input.txt' -o 'C:\Users\***\Desktop\go2\checksubdomains\result4.csv'`))
	fmt.Println(color.Colorize(color.Red, "[*] This tool is for training."))

	// Parse command-line flags for input and output file paths.
	inputfile := flag.String("i", "input.txt", "Input txt File")
	outputfile := flag.String("o", "result.csv", "Output CSV File")
	flag.Parse()

	// Read domain list from the specified text file.
	domains := readDomains(*inputfile)

	var wg sync.WaitGroup
	var results []DomainResult

	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()

			// Check if port 80 is open for the domain.
			port80, err80 := isPortOpen80(domain)

			// Check if port 443 is open for the domain.
			port443, err443 := isPortOpen443(domain)

			// Check if the domain is on a CDN.
			isCDNs, errCDN, CDNname := isCDN(domain)

			result := DomainResult{
				Domain:  domain,
				Port80:  port80 && err80 == nil,
				Port443: port443 && err443 == nil,
				IsCDN:   isCDNs && errCDN == nil,
				CDNname: CDNname,
			}

			// If port 80 or 443 is open, print a message and store the result.
			if result.Port80 || port443 {
				fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
				results = append(results, result)
			}
		}(domain)
	}

	wg.Wait()

	// Write the results to the specified output CSV file.
	writeResults(results, *outputfile)
}

// readDomains reads domain names from a text file and returns them as a string slice.
func readDomains(filename string) []string {
	// Open the file.
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Add domain names to the list.
		domains = append(domains, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	return domains
}

// isPortOpen80 checks if port 80 is open for a domain by making an HTTP GET request.
func isPortOpen80(domain string) (bool, error) {
	_, err := http.Get("http://" + domain)
	if err == nil {
		// If port 80 is open, check the IP address.
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
			return false, err
		}
		fmt.Printf(color.Colorize(color.Green, "[+] %s is up (%s)\n"), domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))
		return false, err
	}
}

// isPortOpen443 checks if port 443 is open for a domain by making an HTTPS GET request.
func isPortOpen443(domain string) (bool, error) {
	_, err := http.Get("https://" + domain)
	if err == nil {
		// If port 443 is open, check the IP address.
		ipAddr, err := net.LookupIP(domain)

		if err != nil {
			fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
			return false, err
		}
		fmt.Printf(color.Colorize(color.Green, "[+] %s is up (%s)\n"), domain, ipAddr[0])
		return true, nil

	} else {
		fmt.Println(color.Colorize(color.Red, "[-] Domain not Resolved"))

		return false, err
	}
}

// isCDN checks if a domain is using a CDN by inspecting the HTTP response headers.
func isCDN(domain string) (bool, error, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Timeout: 2 * time.Second, Transport: tr}
	resp, err := client.Get("http://" + domain)

	if err != nil {
		fmt.Println(err)
		return false, err, "Not"
	}

	defer resp.Body.Close()

	cdnHeaders := []string{"Akamai", "Cloudflare", "Incapsula", "MaxCDN", "Fastly", "CDN77", "Amazon CloudFront", "KeyCDN"}
	for _, header := range cdnHeaders {
		if strings.Contains(resp.Header.Get("Server"), header) || strings.Contains(resp.Header.Get("X-Cache"), header) || strings.Contains(resp.Header.Get("Via"), header) {
			// If the domain is on a CDN, return true and the CDN name.
			return true, nil, header
		}
	}
	return false, nil, "Not"
}

// writeResults writes the results to the specified output CSV file.
func writeResults(results []DomainResult, outputfile string) {
	file, err := os.Create(outputfile)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// Write the results to a CSV file.
	writer := csv.NewWriter(file)
	defer writer.Flush()
	writer.Write([]string{"Domain", "Port 80", "Port 443", "Is CDN", "CDN Name"})
	for _, result := range results {
		writer.Write([]string{result.Domain, fmt.Sprintf("%v", result.Port80), fmt.Sprintf("%v", result.Port443), fmt.Sprintf("%v", result.IsCDN), fmt.Sprintf("%v", result.CDNname)})
	}
}
