package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/projectdiscovery/cdncheck"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// DomainResult represents the result for a single domain, including port status and CDN information.
type DomainResult struct {
	Domain    string
	Port80    bool
	Port443   bool
	IsCDN     bool
	CDNname   string
	isCloud   bool
	CloudName string
	isWAF     bool
	WAFname   string
}

func withpip() []DomainResult {
	scanner := bufio.NewScanner(os.Stdin)
	var results []DomainResult
	for scanner.Scan() {

		domain := scanner.Text()

		// Check if port 80 is open for the domain.
		port80, err80 := isPortOpen80(domain)

		// Check if port 443 is open for the domain.
		port443, err443 := isPortOpen443(domain)

		// Check if the domain is on a CDN.
		isCDNs, CDNname := isCDN(domain)
		isClouds, CloudName := isCloud(domain)
		isWAFs, WAFname := isWaf(domain)

		result := DomainResult{
			Domain:    domain,
			Port80:    port80 && err80 == nil,
			Port443:   port443 && err443 == nil,
			IsCDN:     isCDNs,
			CDNname:   CDNname,
			isCloud:   isClouds,
			CloudName: CloudName,
			isWAF:     isWAFs,
			WAFname:   WAFname,
		}

		// If port 80 or 443 is open, print a message and store the result.
		if result.Port80 || port443 {
			fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
			results = append(results, result)
		}

	}

	return results
}
func withname(domain string) {

	port80, err80 := isPortOpen80(domain)

	// Check if port 443 is open for the domain.
	port443, err443 := isPortOpen443(domain)

	// Check if the domain is on a CDN.
	isCDNs, CDNname := isCDN(domain)
	isClouds, CloudName := isCloud(domain)
	isWAFs, WAFname := isWaf(domain)

	result := DomainResult{
		Domain:    domain,
		Port80:    port80 && err80 == nil,
		Port443:   port443 && err443 == nil,
		IsCDN:     isCDNs,
		CDNname:   CDNname,
		isCloud:   isClouds,
		CloudName: CloudName,
		isWAF:     isWAFs,
		WAFname:   WAFname,
	}

	// If port 80 or 443 is open, print a message and store the result.
	if result.Port80 || port443 {
		fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
		fmt.Printf(color.Colorize(color.Green, "[*] In single-domain mode, the output file is not saved.\n"))
	} else {
		fmt.Printf(color.Colorize(color.Red, "[+] Domain %s is Closed\n"), result.Domain)
		fmt.Printf(color.Colorize(color.Green, "[*] In single-domain mode, the output file is not saved.\n"))
	}
}
func withlist(inputfile string, wg sync.WaitGroup) []DomainResult {
	domains := readDomains(inputfile)
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
			isCDNs, CDNname := isCDN(domain)
			isClouds, CloudName := isCloud(domain)
			isWAFs, WAFname := isWaf(domain)

			result := DomainResult{
				Domain:    domain,
				Port80:    port80 && err80 == nil,
				Port443:   port443 && err443 == nil,
				IsCDN:     isCDNs,
				CDNname:   CDNname,
				isCloud:   isClouds,
				CloudName: CloudName,
				isWAF:     isWAFs,
				WAFname:   WAFname,
			}

			// If port 80 or 443 is open, print a message and store the result.
			if result.Port80 || port443 {
				fmt.Printf(color.Colorize(color.Green, "[+] Domain %s is Opened\n"), result.Domain)
				results = append(results, result)
			}
		}(domain)
	}

	wg.Wait()
	return results
}

func main() {
	// Print usage example and information about the tool.
	fmt.Printf(color.Colorize(color.Green, `Example Of Use : Subcheck.go -i 'C:\Users\**\Desktop\go2\checksubdomains\input.txt' -o 'C:\Users\***\Desktop\go2\checksubdomains\result4.csv'`) + "\n")
	fmt.Println(color.Colorize(color.Red, "[*] This tool is for training."))

	// Parse command-line flags for input and output file paths.
	inputfile := flag.String("l", "", "Input txt File")
	domainname := flag.String("d", "", "Input domain name")
	pipeinsert := flag.Bool("pipe", false, "Input pipe method")
	outputfile := flag.String("o", "result.csv", "Output CSV File")
	flag.Parse()
	if !strings.HasSuffix(*outputfile, ".csv") {
		fmt.Println(color.Colorize(color.Red, "[*] You must Enter CSV file to Export"))
		log.Panic("Error in output file ")
	}
	// Read domain list from the specified text file.

	var wg sync.WaitGroup
	var results []DomainResult
	if *inputfile != "" {
		results = withlist(*inputfile, wg)
	} else if *domainname != "" {
		withname(*domainname)
	} else if *pipeinsert {
		results = withpip()
	} else {
		fmt.Println(color.Colorize(color.Red, "[*] Please Enter input [*]"))
		fmt.Println(color.Colorize(color.Red, "[*] For Example : subcheck -d google.com -o output.csv [*]"))
	}
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
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

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

// isCDN checks if a domain is using a CDN by  IP Address.

func isCDN(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the cdn denylist
	matched, val, err := client.CheckCDN(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s On the CDN (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is Not in CDN\n"), domain)
		return matched, val

	}

	return false, ""
}

// isCloud checks if a domain is using a Cloud by  IP Address.
func isCloud(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the cloud denylist
	matched, val, err := client.CheckCloud(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s On the Cloud (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is Not in Cloud\n"), domain)
		return matched, val

	}

	return false, ""
}

// isWaf checks if a domain is using a Cloud by IP Address.

func isWaf(domain string) (bool, string) {
	// This function checks for CDN presence based on specific headers in the HTTP response.
	ipAddr, err := net.LookupIP(domain)

	if err != nil {
		fmt.Printf(color.Colorize(color.Red, "[-] %s is down\n"), domain)
		return false, ""
	}

	client := cdncheck.New()
	ip := ipAddr[0]

	// checks if an IP is contained in the waf denylist
	matched, val, err := client.CheckWAF(ip)
	if err != nil {
		panic(err)
	}

	if matched {
		fmt.Printf(color.Colorize(color.Green, "[+] %s Has Waf (%s)\n"), domain, val)
		return matched, val

	} else {
		fmt.Printf(color.Colorize(color.Red, "[-] %s has not WAF\n"), domain)
		return matched, val

	}
	return false, ""
}

// writeResults writes the results to the specified output CSV file.
func writeResults(results []DomainResult, outputfile string) {
	file, err := os.Create(outputfile)
	if err != nil {
		panic(err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)
	// Write the results to a CSV file.
	writer := csv.NewWriter(file)
	defer writer.Flush()
	err = writer.Write([]string{"Domain", "Port 80", "Port 443", "Is CDN", "CDN Name", "Is Cloud", "Cloud name", "has Waf", "WAF name"})
	if err != nil {
		return
	}
	for _, result := range results {
		err = writer.Write([]string{result.Domain, fmt.Sprintf("%v", result.Port80), fmt.Sprintf("%v", result.Port443), fmt.Sprintf("%v", result.IsCDN), fmt.Sprintf("%v", result.CDNname), fmt.Sprintf("%v", result.isCloud), fmt.Sprintf("%v", result.CloudName), fmt.Sprintf("%v", result.isWAF), fmt.Sprintf("%v", result.WAFname)})
		if err != nil {
			return
		}
	}
}
